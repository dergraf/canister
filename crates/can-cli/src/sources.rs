//! Recipe sources and `canister.lock` (ADR-0026).
//!
//! A manifest's `[sources]` name recipe repositories: a git repository
//! pinned by a tag or a revision, or a directory next to `canister.toml`.
//! A sandbox names a recipe from one as `<source>/<recipe>`. Git sources
//! are checked out once per revision into a cache and never fetched again.
//!
//! The lock pins each git source to the revision it resolved to and each
//! recipe to the digest of its content. `can up` uses only those pins;
//! `can lock` writes them.

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use can_policy::{LOCK_FILENAME, LockedSource, Lockfile, Manifest, SourceSpec, walk_recipes};

/// Where `can up` and `can lock` find each recipe a manifest names.
pub struct Resolver<'a> {
    manifest: &'a Manifest,
    sources: Vec<(String, PathBuf)>,
}

impl<'a> Resolver<'a> {
    /// A resolver that uses the lock's pins for every git source, fetching
    /// a pinned revision that is not cached yet. A git source the lock does
    /// not pin, or pins for another repository or tag, is an error: the
    /// sandbox would be built from something nobody reviewed.
    pub fn locked(manifest: &'a Manifest, root: &Path, lock: Option<&Lockfile>) -> Result<Self> {
        Self::locked_in(&cache_dir()?, manifest, root, lock)
    }

    fn locked_in(
        cache: &Path,
        manifest: &'a Manifest,
        root: &Path,
        lock: Option<&Lockfile>,
    ) -> Result<Self> {
        let mut sources = Vec::new();
        for (name, spec) in &manifest.sources {
            let dir = match (&spec.git, lock.and_then(|l| l.sources.get(name))) {
                (None, _) => path_source(root, spec),
                (Some(_), None) => bail!(
                    "source '{name}' is a git repository that canister.lock does not pin; run `can lock`"
                ),
                (Some(git), Some(locked)) => {
                    if locked.git.as_deref() != Some(git.as_str()) || locked.tag != spec.tag {
                        bail!(
                            "source '{name}' in canister.toml differs from canister.lock; \
                             review the change and run `can lock --update`"
                        );
                    }
                    let rev = locked
                        .rev
                        .as_deref()
                        .with_context(|| format!("canister.lock pins source '{name}' to no rev"))?;
                    checkout(cache, git, spec.tag.as_deref(), rev)?
                }
            };
            sources.push((name.clone(), dir));
        }
        Ok(Self { manifest, sources })
    }

    /// A resolver for `can lock`: git sources keep the revision `previous`
    /// pins unless `update` is set or the manifest names another
    /// repository or tag; otherwise the tag (or `rev`) is resolved afresh.
    /// Returns the locked sources alongside.
    pub fn resolving(
        manifest: &'a Manifest,
        root: &Path,
        previous: Option<&Lockfile>,
        update: bool,
    ) -> Result<(Self, std::collections::BTreeMap<String, LockedSource>)> {
        Self::resolving_in(&cache_dir()?, manifest, root, previous, update)
    }

    fn resolving_in(
        cache: &Path,
        manifest: &'a Manifest,
        root: &Path,
        previous: Option<&Lockfile>,
        update: bool,
    ) -> Result<(Self, std::collections::BTreeMap<String, LockedSource>)> {
        let mut locked = std::collections::BTreeMap::new();
        let mut sources = Vec::new();

        for (name, spec) in &manifest.sources {
            let (dir, entry) = match &spec.git {
                None => (
                    path_source(root, spec),
                    LockedSource {
                        path: spec.path.as_ref().map(|p| p.display().to_string()),
                        ..LockedSource::default()
                    },
                ),
                Some(git) => {
                    let kept = previous
                        .and_then(|lock| lock.sources.get(name))
                        .filter(|old| {
                            !update
                                && old.git.as_deref() == Some(git.as_str())
                                && old.tag == spec.tag
                        })
                        .and_then(|old| old.rev.clone());
                    let rev = match (kept, &spec.rev) {
                        (Some(rev), _) => rev,
                        (None, Some(rev)) => rev.clone(),
                        (None, None) => {
                            resolve_tag(cache, git, spec.tag.as_deref().unwrap_or_default())?
                        }
                    };
                    let dir = checkout(cache, git, spec.tag.as_deref(), &rev)?;
                    (
                        dir,
                        LockedSource {
                            git: Some(git.clone()),
                            tag: spec.tag.clone(),
                            rev: Some(rev),
                            path: None,
                        },
                    )
                }
            };
            locked.insert(name.clone(), entry);
            sources.push((name.clone(), dir));
        }

        Ok((Self { manifest, sources }, locked))
    }

    /// The file a recipe name stands for: `<source>/<recipe>` in a declared
    /// source (by stem, recursively, or as a path within it), anything else
    /// as `can run --recipe` resolves it.
    pub fn resolve(&self, recipe: &str) -> Result<PathBuf> {
        let Some((source, rest)) = self.manifest.source_recipe(recipe) else {
            return crate::commands::resolve_recipe_path(recipe);
        };
        let dir = self
            .sources
            .iter()
            .find(|(name, _)| name == source)
            .map(|(_, dir)| dir)
            .with_context(|| format!("source '{source}' was not resolved"))?;

        let as_path = dir.join(rest).with_extension("toml");
        if rest.contains('/') && as_path.is_file() {
            return Ok(as_path);
        }

        let matches: Vec<PathBuf> = walk_recipes(dir)
            .into_iter()
            .filter(|p| p.file_stem().and_then(|s| s.to_str()) == Some(rest))
            .collect();
        match matches.as_slice() {
            [one] => Ok(one.clone()),
            [] => bail!(
                "recipe '{rest}' not found in source '{source}' ({})",
                dir.display()
            ),
            _ => bail!("recipe '{rest}' is ambiguous in source '{source}'; name it by path"),
        }
    }
}

/// Read the lock next to the manifest, `None` when there is none.
pub fn read_lock(root: &Path) -> Result<Option<Lockfile>> {
    let path = root.join(LOCK_FILENAME);
    match std::fs::read_to_string(&path) {
        Ok(content) => Lockfile::parse(&content)
            .map(Some)
            .with_context(|| format!("reading {}", path.display())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("reading {}", path.display())),
    }
}

/// `can lock`: pin every source and every recipe the manifest's sandboxes
/// compose, and write `canister.lock` next to the manifest.
pub fn lock(update: bool) -> Result<i32> {
    let cwd = std::env::current_dir().context("getting current directory")?;
    let manifest_path = can_policy::discover_manifest(&cwd)
        .context("no canister.toml found; `can lock` pins the recipes a canister.toml names")?;
    let manifest = Manifest::from_file(&manifest_path)
        .with_context(|| format!("parsing {}", manifest_path.display()))?;
    let root = manifest_path
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();

    let previous = read_lock(&root)?;
    let (resolver, sources) = Resolver::resolving(&manifest, &root, previous.as_ref(), update)?;

    let mut lock = Lockfile::new();
    lock.sources = sources;
    for name in manifest.sandbox_names() {
        // SAFETY-UNWRAP: the name came from this manifest.
        for recipe in &manifest.get(name).unwrap().recipes {
            let path = resolver.resolve(recipe)?;
            let content = std::fs::read_to_string(&path)
                .with_context(|| format!("reading {}", path.display()))?;
            lock.recipes
                .insert(recipe.clone(), can_policy::lock::digest(&content));
        }
    }

    let lock_path = root.join(LOCK_FILENAME);
    std::fs::write(&lock_path, lock.render())
        .with_context(|| format!("writing {}", lock_path.display()))?;

    for (name, source) in &lock.sources {
        if let Some(rev) = &source.rev {
            println!("pinned {name} at {}", &rev[..rev.len().min(12)]);
        }
    }
    for (name, digest) in &lock.recipes {
        println!("locked {name} {}", &digest[..12]);
    }
    println!(
        "wrote {}; commit it with canister.toml",
        lock_path.display()
    );
    Ok(0)
}

fn path_source(root: &Path, spec: &SourceSpec) -> PathBuf {
    root.join(spec.path.as_deref().unwrap_or(Path::new(".")))
}

/// The commit a tag points to, by cloning it.
fn resolve_tag(cache: &Path, git: &str, tag: &str) -> Result<String> {
    let tmp = cache.join(format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    clone_tag(git, tag, &tmp)?;
    let rev = rev_parse(&tmp)?;
    let final_dir = source_dir(cache, git, &rev);
    if final_dir.is_dir() {
        let _ = std::fs::remove_dir_all(&tmp);
    } else {
        move_into_place(&tmp, &final_dir)?;
    }
    Ok(rev)
}

/// A checkout of `git` at `rev`, from the cache or fetched into it. With a
/// tag, the tag is cloned and must still point at `rev`.
fn checkout(cache: &Path, git: &str, tag: Option<&str>, rev: &str) -> Result<PathBuf> {
    let dir = source_dir(cache, git, rev);
    if dir.is_dir() {
        return Ok(dir);
    }

    let tmp = dir.with_extension(format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    match tag {
        Some(tag) => {
            clone_tag(git, tag, &tmp)?;
            let actual = rev_parse(&tmp)?;
            if actual != rev {
                let _ = std::fs::remove_dir_all(&tmp);
                bail!(
                    "tag {tag} of {git} moved: canister.lock pins {} but it now points at {}; \
                     review the change and run `can lock --update`",
                    short(rev),
                    short(&actual)
                );
            }
        }
        None => fetch_rev(git, rev, &tmp)?,
    }
    move_into_place(&tmp, &dir)?;
    Ok(dir)
}

fn clone_tag(git: &str, tag: &str, dest: &Path) -> Result<()> {
    run_git(
        None,
        &[
            "-c",
            "advice.detachedHead=false",
            "clone",
            "--quiet",
            "--depth",
            "1",
            "--branch",
            tag,
            git,
            &dest.display().to_string(),
        ],
    )
    .with_context(|| format!("fetching tag {tag} of {git}"))
}

fn fetch_rev(git: &str, rev: &str, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    run_git(Some(dest), &["init", "--quiet"])?;
    run_git(Some(dest), &["fetch", "--quiet", "--depth", "1", git, rev])
        .with_context(|| format!("fetching {} of {git}", short(rev)))?;
    run_git(
        Some(dest),
        &[
            "-c",
            "advice.detachedHead=false",
            "checkout",
            "--quiet",
            "FETCH_HEAD",
        ],
    )
}

fn rev_parse(dir: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dir)
        .output()
        .context("running git rev-parse")?;
    if !output.status.success() {
        bail!("git rev-parse failed in {}", dir.display());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

fn run_git(dir: Option<&Path>, args: &[&str]) -> Result<()> {
    let mut command = Command::new("git");
    command.args(args);
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    let output = command.output().context("running git (is it installed?)")?;
    if !output.status.success() {
        bail!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn move_into_place(from: &Path, to: &Path) -> Result<()> {
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    std::fs::rename(from, to).with_context(|| format!("moving checkout to {}", to.display()))
}

/// `<cache>/<sha256 of the repository url, 16 hex>/<rev>`.
fn source_dir(cache: &Path, git: &str, rev: &str) -> PathBuf {
    let key = can_policy::lock::digest(git);
    cache.join(&key[..16]).join(rev)
}

fn cache_dir() -> Result<PathBuf> {
    let base = match std::env::var_os("XDG_CACHE_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(std::env::var_os("HOME").context("HOME is not set")?).join(".cache"),
    };
    Ok(base.join("canister/sources"))
}

fn short(rev: &str) -> &str {
    &rev[..rev.len().min(12)]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.com"])
            .args(args)
            .current_dir(dir)
            .output()
            .expect("git");
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    /// A recipe repository with `internal.toml`, tagged `v1`.
    fn recipe_repo(dir: &Path) -> (String, String) {
        std::fs::create_dir_all(dir).expect("repo dir");
        git(dir, &["init", "--quiet", "--initial-branch", "main"]);
        git(dir, &["config", "uploadpack.allowAnySHA1InWant", "true"]);
        std::fs::write(
            dir.join("internal.toml"),
            "[[host]]\ndomain = \"internal.example\"\n",
        )
        .expect("recipe");
        git(dir, &["add", "-A"]);
        git(dir, &["commit", "--quiet", "-m", "v1"]);
        git(dir, &["tag", "v1"]);
        (
            format!("file://{}", dir.display()),
            git(dir, &["rev-parse", "HEAD"]),
        )
    }

    fn manifest(source: &str) -> Manifest {
        Manifest::parse(&format!(
            "[sources]\nteam = {source}\n\n[sandbox.ci]\nrecipes = [\"team/internal\"]\ncommand = \"true\"\n"
        ))
        .expect("manifest")
    }

    #[test]
    fn a_tag_is_pinned_to_its_commit_and_the_recipe_found_in_it() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (url, rev) = recipe_repo(&tmp.path().join("repo"));
        let manifest = manifest(&format!("{{ git = \"{url}\", tag = \"v1\" }}"));
        let cache = tmp.path().join("cache");

        let (resolver, locked) =
            Resolver::resolving_in(&cache, &manifest, tmp.path(), None, false).expect("lock");

        assert_eq!(locked["team"].rev.as_deref(), Some(rev.as_str()));
        let path = resolver.resolve("team/internal").expect("resolved");
        assert!(path.starts_with(cache.join(&can_policy::lock::digest(&url)[..16]).join(&rev)));
    }

    #[test]
    fn a_locked_run_uses_the_pin_even_after_the_tag_moved_in_the_cache() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path().join("repo");
        let (url, rev) = recipe_repo(&repo);
        let manifest = manifest(&format!("{{ git = \"{url}\", tag = \"v1\" }}"));
        let cache = tmp.path().join("cache");
        let (_resolver, sources) =
            Resolver::resolving_in(&cache, &manifest, tmp.path(), None, false).expect("lock");
        let lock = Lockfile {
            sources,
            ..Lockfile::new()
        };

        // The tag moves upstream; the cached checkout of the pinned rev wins.
        std::fs::write(repo.join("internal.toml"), "# changed\n").expect("change");
        git(&repo, &["commit", "--quiet", "-am", "v1 again"]);
        git(&repo, &["tag", "-f", "v1"]);

        let resolver =
            Resolver::locked_in(&cache, &manifest, tmp.path(), Some(&lock)).expect("locked");
        let path = resolver.resolve("team/internal").expect("resolved");
        assert!(path.to_string_lossy().contains(&rev));
    }

    #[test]
    fn a_tag_that_moved_is_refused_when_its_pin_must_be_fetched() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = tmp.path().join("repo");
        let (url, rev) = recipe_repo(&repo);
        std::fs::write(repo.join("internal.toml"), "# changed\n").expect("change");
        git(&repo, &["commit", "--quiet", "-am", "moved"]);
        git(&repo, &["tag", "-f", "v1"]);

        let error =
            checkout(&tmp.path().join("cache"), &url, Some("v1"), &rev).expect_err("moved tag");

        assert!(format!("{error:#}").contains("moved"));
    }

    #[test]
    fn a_rev_without_a_tag_is_fetched_by_commit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (url, rev) = recipe_repo(&tmp.path().join("repo"));
        let manifest = manifest(&format!("{{ git = \"{url}\", rev = \"{rev}\" }}"));

        let (resolver, locked) = Resolver::resolving_in(
            &tmp.path().join("cache"),
            &manifest,
            tmp.path(),
            None,
            false,
        )
        .expect("lock");

        assert_eq!(locked["team"].rev.as_deref(), Some(rev.as_str()));
        assert!(resolver.resolve("team/internal").is_ok());
    }

    #[test]
    fn a_git_source_without_a_pin_is_refused_for_a_run() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest = manifest("{ git = \"file:///nowhere\", tag = \"v1\" }");

        let error = Resolver::locked_in(
            &tmp.path().join("cache"),
            &manifest,
            tmp.path(),
            Some(&Lockfile::new()),
        )
        .err()
        .expect("unpinned");

        assert!(format!("{error:#}").contains("does not pin"));
    }

    #[test]
    fn a_source_changed_in_canister_toml_needs_a_new_lock() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let manifest = manifest("{ git = \"file:///nowhere\", tag = \"v2\" }");
        let mut lock = Lockfile::new();
        lock.sources.insert(
            "team".to_string(),
            LockedSource {
                git: Some("file:///nowhere".to_string()),
                tag: Some("v1".to_string()),
                rev: Some("a".repeat(40)),
                path: None,
            },
        );

        let error = Resolver::locked_in(
            &tmp.path().join("cache"),
            &manifest,
            tmp.path(),
            Some(&lock),
        )
        .err()
        .expect("changed source");

        assert!(format!("{error:#}").contains("can lock --update"));
    }
}
