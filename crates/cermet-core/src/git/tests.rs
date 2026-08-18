//! Red-first coverage of the git seam. Everything here is OFFLINE: local bare repos and `file://`
//! upstreams exercise the whole hop, including git's native fast-forward refusal.

use super::*;

const SYSTEM_GIT: &str = "/usr/bin/git";

struct Fixture {
    _dir: tempfile::TempDir,
    root: PathBuf,
    cfg: GitConfig,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let root = dir.path().to_path_buf();
        let cfg = GitConfig::at(root.join("mirrors")).with_binary(SYSTEM_GIT);
        Fixture {
            _dir: dir,
            root,
            cfg,
        }
    }

    /// Fixture plumbing, deliberately NOT hermetic — this stands in for a developer's own git.
    fn git(&self, cwd: &Path, args: &[&str]) -> String {
        let out = Command::new(SYSTEM_GIT)
            .args(args)
            .current_dir(cwd)
            .env("HOME", &self.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@example.invalid")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@example.invalid")
            .output()
            .expect("fixture git runs");
        assert!(
            out.status.success(),
            "fixture git {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).trim().to_string()
    }

    fn bare(&self, name: &str) -> PathBuf {
        let path = self.root.join(name);
        std::fs::create_dir_all(path.parent().unwrap_or(&self.root)).unwrap();
        self.git(
            &self.root,
            &["init", "-q", "--bare", path.to_str().unwrap()],
        );
        path
    }

    /// A source repo with one commit touching two paths; returns its oid.
    fn source(&self) -> (PathBuf, String) {
        let src = self.root.join("src");
        std::fs::create_dir_all(src.join("docs")).unwrap();
        self.git(&src, &["init", "-q", "-b", "main", "."]);
        std::fs::write(src.join("README.md"), "hello\n").unwrap();
        std::fs::write(src.join("docs/guide.md"), "guide\n").unwrap();
        self.git(&src, &["add", "-A"]);
        self.git(&src, &["commit", "-q", "-m", "one"]);
        let oid = self.git(&src, &["rev-parse", "HEAD"]);
        (src, oid)
    }

    fn repo(&self) -> RepoId {
        RepoId::parse("github/acme/website").unwrap()
    }

    /// A no-op hook program, so `ensure_mirror` has something to install.
    fn hook_program(&self) -> PathBuf {
        let path = self.root.join("hook-noop");
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn ref_of(&self, repo: &Path, branch: &str) -> Option<String> {
        let out = Command::new(SYSTEM_GIT)
            .args([
                "--git-dir",
                repo.to_str().unwrap(),
                "rev-parse",
                &format!("refs/heads/{branch}"),
            ])
            .env("HOME", &self.root)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .output()
            .unwrap();
        out.status
            .success()
            .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
    }
}

// ---------------------------------------------------------------------------
// Usability (git is DEFAULTED, checked per request, never required at boot)
// ---------------------------------------------------------------------------

#[test]
fn the_default_git_is_the_boxs_git_at_a_root_owned_absolute_path() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = GitConfig::at(dir.path());
    assert_eq!(cfg.binary, PathBuf::from(DEFAULT_GIT_BINARY));
    assert!(
        cfg.binary.is_absolute(),
        "an absolute path is what makes PATH substitution impossible (T3)"
    );
    assert_eq!(usable(&cfg).unwrap(), PathBuf::from(SYSTEM_GIT));
}

#[test]
fn an_unusable_git_refuses_legibly_and_names_the_setting() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = GitConfig::at(dir.path()).with_binary(dir.path().join("no-such-git"));

    let error = usable(&cfg).expect_err("a missing git refuses");
    let message = error.to_string();
    assert!(message.contains("is not usable"), "{message}");
    assert!(
        message.contains("git_binary"),
        "the refusal names the setting"
    );
    assert!(
        message.contains("every other verb is unaffected"),
        "the refusal is per-request, not a boot failure: {message}"
    );
}

#[test]
fn the_version_floor_is_checked_on_use() {
    let f = Fixture::new();
    let reported = preflight(&f.cfg).expect("the system git satisfies the minimum");
    assert!(reported.starts_with("git version "), "{reported}");
}

#[test]
fn a_binary_that_is_not_git_refuses() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = GitConfig::at(dir.path()).with_binary("/bin/echo");
    let error = preflight(&cfg).expect_err("echo is not git");
    assert!(
        format!("{error}").contains("unparseable version"),
        "{error}"
    );
}

#[test]
fn no_path_lookup_exists_to_fall_back_on() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = GitConfig::at(dir.path()).with_binary("git");
    let error = usable(&cfg).expect_err("a bare name is never resolved through PATH");
    assert!(format!("{error}").contains("is not usable"), "{error}");
}

#[test]
fn version_parsing_is_exact() {
    assert_eq!(parse_version("git version 2.53.0"), Some((2, 53)));
    assert_eq!(
        parse_version("git version 2.31.1 (Apple Git-1)"),
        Some((2, 31))
    );
    assert_eq!(parse_version("git version 2.30.9"), Some((2, 30)));
    assert!(parse_version("2.53.0").is_none());
    assert!(parse_version("git version x.y").is_none());
    assert!((2, 30) < MIN_GIT_VERSION, "2.30 predates GIT_CONFIG_COUNT");
}

// ---------------------------------------------------------------------------
// Hermeticity and the credential channel
// ---------------------------------------------------------------------------

#[test]
fn the_child_environment_is_hermetic_and_carries_no_box_config() {
    let f = Fixture::new();
    let poisoned = f.root.join("poison.gitconfig");
    std::fs::write(&poisoned, "[http]\n\tproxy = http://evil.invalid\n").unwrap();
    std::env::set_var("GIT_CONFIG_GLOBAL", &poisoned);
    let run = run(&f.cfg, None, &["config", "--get", "http.proxy"], None, None).unwrap();
    std::env::remove_var("GIT_CONFIG_GLOBAL");
    assert_eq!(run.code, Some(1), "an unset key exits 1");
    assert!(run.stdout.is_empty(), "box config must not bleed in");
}

#[test]
fn a_credential_rides_environment_config_and_never_argv() {
    let f = Fixture::new();
    let cred = GitCredential {
        url: "https://github.invalid/o/n.git".into(),
        header: "Authorization: Basic c2VjcmV0".into(),
    };
    // Ask git what it thinks the config is — the only way it could know is the environment channel.
    let run = run(
        &f.cfg,
        None,
        &[
            "config",
            "--get",
            "http.https://github.invalid/o/n.git.extraHeader",
        ],
        None,
        Some(&cred),
    )
    .unwrap();
    assert!(run.ok(), "{}", run.stderr);
    assert_eq!(
        String::from_utf8_lossy(&run.stdout).trim(),
        "Authorization: Basic c2VjcmV0"
    );
}

#[test]
fn a_wedged_invocation_is_killed_at_the_timeout() {
    let f = Fixture::new();
    let cfg = GitConfig {
        timeout: Duration::from_millis(300),
        ..f.cfg.clone()
    };
    let run = run(
        &cfg,
        None,
        &["hash-object", "-t", "blob", "--stdin"],
        Some(Path::new("/dev/zero")),
        None,
    )
    .expect("the runner returns rather than hanging");
    assert!(run.timed_out, "the watchdog must fire");
    assert!(!run.ok());
}

/// The watchdog signals the whole PROCESS GROUP, so a GRANDCHILD holding the same pipe
/// write ends cannot keep `run()` blocked past the declared timeout. Reproduced with git's own
/// `-c alias` machinery: the alias runs a shell that spawns a long sleeper and exits, leaving the
/// sleeper holding stdout — the exact shape `git-remote-https` had.
#[test]
fn the_watchdog_kills_the_whole_process_group_not_just_the_direct_child() {
    let f = Fixture::new();
    let cfg = GitConfig {
        timeout: Duration::from_millis(400),
        ..f.cfg.clone()
    };
    let started = Instant::now();
    let run = run(
        &cfg,
        None,
        &[
            "-c",
            // Absolute paths: the hermetic PATH is git's own bindir, and macOS keeps `sh` and
            // `sleep` in /bin, so bare names resolve on Linux only.
            "alias.holdpipe=!/bin/sh -c '/bin/sleep 60 & exit 0'",
            "holdpipe",
        ],
        None,
        None,
    )
    .expect("the runner returns");
    let elapsed = started.elapsed();
    assert!(run.timed_out, "the watchdog fired");
    assert!(
        elapsed < Duration::from_secs(5),
        "a pipe-holding grandchild must not outlive the deadline (took {elapsed:?})"
    );
}

// ---------------------------------------------------------------------------
// Repo identity
// ---------------------------------------------------------------------------

#[test]
fn a_repo_identity_validates_before_any_path_is_joined() {
    let good = RepoId::parse("github/acme/website").unwrap();
    assert_eq!(good.provider, "github");
    assert_eq!(good.slug(), "acme/website");
    assert_eq!(RepoId::parse("github/acme/website.git").unwrap(), good);

    for hostile in [
        "github/../../evil/x",
        "github/acme/../../../etc",
        "github/./x",
        "github/-rf/x",
        "github/acme/we bsite",
        "github/acme/web\nsite",
        "github/acme/web\0site",
        "github/acme",
        "github/acme/x/y",
        "github//x",
        "",
    ] {
        assert!(
            RepoId::parse(hostile).is_err(),
            "`{hostile}` must never become a mirror path"
        );
    }
    assert!(!is_valid_repo_segment(&"a".repeat(101)));
    assert!(is_valid_repo_segment(&"a".repeat(100)));
}

// ---------------------------------------------------------------------------
// The persistent mirror
// ---------------------------------------------------------------------------

#[test]
fn a_mirror_is_created_on_first_contact_private_and_bare_with_a_hook() {
    let f = Fixture::new();
    let hook = f.hook_program();
    assert!(!f.cfg.mirror_dir.exists(), "nothing is created eagerly");

    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    assert!(
        mirror.join("objects").is_dir(),
        "a bare repo was initialized"
    );
    assert!(mirror.ends_with("github/acme/website.git"));
    let installed = std::fs::read_to_string(mirror.join("hooks/update")).unwrap();
    assert!(
        installed.contains("git-update-hook") && installed.contains(hook.to_str().unwrap()),
        "the update hook execs the daemon: {installed}"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&mirror).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "mirrors are daemon-private (T3)");
    }
}

#[test]
fn a_mirror_persists_across_contacts_and_keeps_its_objects() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let (src, oid) = f.source();
    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    // Seed it the way receive-pack would.
    f.git(&src, &["push", "-q", mirror.to_str().unwrap(), "main"]);

    // Second contact: same mirror, objects still there. THIS is what makes every later push
    // O(delta) and what a per-request quarantine could never do.
    let again = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    assert_eq!(mirror, again);
    let present = run(&f.cfg, Some(&mirror), &["cat-file", "-e", &oid], None, None).unwrap();
    assert!(present.ok(), "prior traffic's objects survive");
}

#[test]
fn the_hook_is_reinstalled_on_every_contact_so_it_can_never_go_stale() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    std::fs::write(mirror.join("hooks/update"), "#!/bin/sh\nexit 0\n").unwrap();

    let moved = f.root.join("cermetd-v2");
    std::fs::write(&moved, "#!/bin/sh\nexit 0\n").unwrap();
    ensure_mirror(&f.cfg, &f.repo(), &moved).unwrap();
    let installed = std::fs::read_to_string(mirror.join("hooks/update")).unwrap();
    assert!(
        installed.contains(moved.to_str().unwrap()),
        "a mirror whose hook does not run is a mirror with no authorization on it: {installed}"
    );
}

#[test]
fn the_startup_sweep_ages_out_mirrors_with_no_recent_contact() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let stale = ensure_mirror(&f.cfg, &RepoId::parse("github/acme/old").unwrap(), &hook).unwrap();
    let fresh = ensure_mirror(&f.cfg, &RepoId::parse("github/acme/new").unwrap(), &hook).unwrap();
    let now = crate::util::now_epoch();
    touch_at(&stale.join(CONTACT_STAMP), now - 200 * 86_400);

    assert_eq!(purge_expired_mirrors(&f.cfg, now), 1);
    assert!(!stale.exists());
    assert!(fresh.exists());
}

#[test]
fn retention_zero_keeps_mirrors_forever() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let cfg = GitConfig {
        mirror_retention_days: 0,
        ..f.cfg.clone()
    };
    let mirror = ensure_mirror(&cfg, &f.repo(), &hook).unwrap();
    touch_at(&mirror.join(CONTACT_STAMP), 0);
    assert_eq!(purge_expired_mirrors(&cfg, crate::util::now_epoch()), 0);
    assert!(mirror.exists());
}

#[test]
fn gc_is_hygiene_that_leaves_a_healthy_mirror_alone() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let (src, oid) = f.source();
    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    f.git(&src, &["push", "-q", mirror.to_str().unwrap(), "main"]);
    gc_mirror(&f.cfg, &mirror).expect("gc --auto is a no-op below git's own thresholds");
    let present = run(&f.cfg, Some(&mirror), &["cat-file", "-e", &oid], None, None).unwrap();
    assert!(present.ok(), "gc never loses reachable objects");
}

/// Set mtime in-process: `touch -d @epoch` is a GNU extension BSD touch rejects, and this
/// fixture has to run on both platforms.
fn touch_at(path: &Path, epoch: i64) {
    let when = std::time::UNIX_EPOCH + std::time::Duration::from_secs(epoch as u64);
    // Read-only is enough for futimens; the orphan case hands us a directory.
    std::fs::File::open(path)
        .expect("the path exists")
        .set_times(std::fs::FileTimes::new().set_modified(when))
        .expect("mtime is settable");
}

// ---------------------------------------------------------------------------
// The streamed services
// ---------------------------------------------------------------------------

#[test]
fn the_service_names_are_a_closed_set() {
    assert_eq!(
        GitService::parse("receive-pack"),
        Some(GitService::ReceivePack)
    );
    assert_eq!(
        GitService::parse("git-upload-pack"),
        Some(GitService::UploadPack)
    );
    for hostile in ["daemon", "shell", "rm", "", "upload-archive"] {
        assert!(
            GitService::parse(hostile).is_none(),
            "`{hostile}` is not a service this plane serves"
        );
    }
}

#[test]
fn a_service_command_is_hermetic_and_needs_a_usable_git() {
    let f = Fixture::new();
    let mirror = ensure_mirror(&f.cfg, &f.repo(), &f.hook_program()).unwrap();
    let command = service_command(&f.cfg, GitService::ReceivePack, &mirror).unwrap();
    let rendered = format!("{command:?}");
    assert!(rendered.contains("receive-pack"), "{rendered}");

    let dir = tempfile::tempdir().unwrap();
    let broken = GitConfig::at(dir.path()).with_binary(dir.path().join("no-such-git"));
    assert!(
        service_command(&broken, GitService::ReceivePack, &mirror).is_err(),
        "no usable git, no service"
    );
}

// ---------------------------------------------------------------------------
// Derived facts
// ---------------------------------------------------------------------------

#[test]
fn changed_paths_are_derived_from_gits_own_objects_in_the_mirror() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let (src, first) = f.source();
    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    f.git(&src, &["push", "-q", mirror.to_str().unwrap(), "main"]);

    // A creation diffs against the commit's own root: everything added.
    let created = changed_paths(&f.cfg, &mirror, NULL_OID, &first).unwrap();
    assert_eq!(created.total, 2);
    assert!(created.rows.iter().all(|row| row.status == "A"));
    assert!(!created.truncated);

    std::fs::write(src.join("README.md"), "changed\n").unwrap();
    std::fs::remove_file(src.join("docs/guide.md")).unwrap();
    std::fs::write(src.join("new.txt"), "new\n").unwrap();
    f.git(&src, &["add", "-A"]);
    f.git(&src, &["commit", "-q", "-m", "two"]);
    let second = f.git(&src, &["rev-parse", "HEAD"]);
    f.git(&src, &["push", "-q", mirror.to_str().unwrap(), "main"]);

    let updated = changed_paths(&f.cfg, &mirror, &first, &second).unwrap();
    assert_eq!(updated.total, 3);
    let mut rows: Vec<(String, String)> = updated
        .rows
        .iter()
        .map(|r| (r.status.clone(), r.path.clone()))
        .collect();
    rows.sort();
    assert_eq!(
        rows,
        vec![
            ("A".to_string(), "new.txt".to_string()),
            ("D".to_string(), "docs/guide.md".to_string()),
            ("M".to_string(), "README.md".to_string()),
        ]
    );
}

#[test]
fn the_changed_path_list_is_row_capped_with_saturating_counts() {
    // Pure parser test — no allocation bomb, just more rows than the cap.
    let rows = MAX_CHANGED_ROWS + 37;
    let mut raw = Vec::new();
    for i in 0..rows {
        raw.extend_from_slice(b"A\0");
        raw.extend_from_slice(format!("path/{i}.txt").as_bytes());
        raw.push(0);
    }
    let parsed = parse_name_status(&raw);
    assert_eq!(parsed.rows.len(), MAX_CHANGED_ROWS);
    assert!(parsed.truncated);
    assert_eq!(parsed.total, rows as u64);
}

#[test]
fn an_over_long_path_is_counted_but_never_rendered_as_a_different_path() {
    let mut raw = Vec::from(&b"A\0"[..]);
    raw.extend(std::iter::repeat_n(b'x', MAX_PATH_BYTES + 1));
    raw.push(0);
    raw.extend_from_slice(b"M\0ok.txt\0");
    let parsed = parse_name_status(&raw);
    assert_eq!(parsed.total, 2);
    assert_eq!(parsed.rows.len(), 1);
    assert_eq!(parsed.rows[0].path, "ok.txt");
    assert!(parsed.truncated);
}

// ---------------------------------------------------------------------------
// The credentialed hop
// ---------------------------------------------------------------------------

#[test]
fn the_hop_carries_the_mirrors_objects_to_a_local_upstream() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let (src, oid) = f.source();
    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    f.git(&src, &["push", "-q", mirror.to_str().unwrap(), "main"]);
    let upstream = f.bare("upstream.git");

    carry_to_upstream(
        &f.cfg,
        &mirror,
        &format!("file://{}", upstream.display()),
        None,
        &oid,
        "main",
    )
    .expect("the hop lands");
    assert_eq!(f.ref_of(&upstream, "main").as_deref(), Some(oid.as_str()));
}

#[test]
fn the_upstreams_own_fast_forward_rule_is_the_concurrency_control() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let (src, first) = f.source();
    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    let upstream = f.bare("upstream.git");
    let url = format!("file://{}", upstream.display());
    f.git(&src, &["push", "-q", mirror.to_str().unwrap(), "main"]);
    carry_to_upstream(&f.cfg, &mirror, &url, None, &first, "main").unwrap();

    // Somebody else advanced the upstream out from under us.
    std::fs::write(src.join("README.md"), "theirs\n").unwrap();
    f.git(&src, &["add", "-A"]);
    f.git(&src, &["commit", "-q", "-m", "theirs"]);
    let theirs = f.git(&src, &["rev-parse", "HEAD"]);
    f.git(&src, &["push", "-q", upstream.to_str().unwrap(), "main"]);

    // Our divergent tip: a sibling of `first`, not a descendant of the upstream head.
    f.git(&src, &["reset", "-q", "--hard", &first]);
    std::fs::write(src.join("README.md"), "ours\n").unwrap();
    f.git(&src, &["add", "-A"]);
    f.git(&src, &["commit", "-q", "-m", "ours"]);
    let ours = f.git(&src, &["rev-parse", "HEAD"]);
    f.git(
        &src,
        &[
            "push",
            "-q",
            "-f",
            mirror.to_str().unwrap(),
            "HEAD:refs/heads/main",
        ],
    );

    let error = carry_to_upstream(&f.cfg, &mirror, &url, None, &ours, "main")
        .expect_err("a non-fast-forward is the upstream's refusal, not ours");
    assert!(format!("{error}").contains("upstream refused"), "{error}");
    assert_eq!(
        f.ref_of(&upstream, "main").as_deref(),
        Some(theirs.as_str()),
        "the upstream head is untouched"
    );
}

#[test]
fn the_hop_creates_a_branch_that_does_not_exist_upstream_yet() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let (src, oid) = f.source();
    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    f.git(&src, &["push", "-q", mirror.to_str().unwrap(), "main"]);
    let upstream = f.bare("upstream.git");

    carry_to_upstream(
        &f.cfg,
        &mirror,
        &format!("file://{}", upstream.display()),
        None,
        &oid,
        "feature/brand-new",
    )
    .expect("creating is the same effect as advancing");
    assert_eq!(
        f.ref_of(&upstream, "feature/brand-new").as_deref(),
        Some(oid.as_str())
    );
}

// ---------------------------------------------------------------------------
// The upstream's OWN account of the transition it performed
// ---------------------------------------------------------------------------

#[test]
fn the_upstream_transition_parser_reads_both_shapes_git_emits() {
    let created = parse_upstream_transition(
        b"To file:///x\n*\t1111111111111111111111111111111111111111:refs/heads/main\t[new branch]\nDone\n",
        "main",
    )
    .expect("a creation parses");
    assert!(created.created);
    assert_eq!(created.from, None);

    let from = "a".repeat(40);
    let to = "b".repeat(40);
    let line = format!("To file:///x\n \t{to}:refs/heads/main\t{from}..{to}\nDone\n");
    let updated = parse_upstream_transition(line.as_bytes(), "main").expect("an update parses");
    assert!(!updated.created);
    assert_eq!(updated.from.as_deref(), Some(from.as_str()));

    // A different branch's line is not this branch's transition.
    assert!(parse_upstream_transition(line.as_bytes(), "other").is_none());
    // An abbreviated oid is not an identity: refuse rather than record a partial value.
    let abbrev = "To file:///x\n \tb:refs/heads/main\t2069e9f..e77fabe\nDone\n";
    assert!(parse_upstream_transition(abbrev.as_bytes(), "main").is_none());
    // Garbage yields None, never a fabricated oid.
    assert!(parse_upstream_transition(b"", "main").is_none());
    assert!(parse_upstream_transition(b"To x\nDone\n", "main").is_none());
}

#[test]
fn the_hop_reports_the_upstreams_from_oid_not_the_mirrors_tip() {
    // The exact divergence this guards: a third party advances the upstream while the mirror
    // stays behind, so the mirror's `old` and the upstream's real `from` are different commits.
    let f = Fixture::new();
    let hook = f.hook_program();
    let (src, first) = f.source();
    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    let upstream = f.bare("upstream.git");
    let url = format!("file://{}", upstream.display());

    // Both start at `first`; the mirror stops here (there is no fetch refresh).
    f.git(&src, &["push", "-q", mirror.to_str().unwrap(), "main"]);
    carry_to_upstream(&f.cfg, &mirror, &url, None, &first, "main").unwrap();

    // A third party pushes `theirs` straight to the upstream.
    std::fs::write(src.join("theirs.txt"), "theirs\n").unwrap();
    f.git(&src, &["add", "-A"]);
    f.git(&src, &["commit", "-q", "-m", "theirs"]);
    let theirs = f.git(&src, &["rev-parse", "HEAD"]);
    f.git(&src, &["push", "-q", upstream.to_str().unwrap(), "main"]);

    // The agent builds on `theirs` and pushes through us. The mirror's tip is still `first`.
    std::fs::write(src.join("ours.txt"), "ours\n").unwrap();
    f.git(&src, &["add", "-A"]);
    f.git(&src, &["commit", "-q", "-m", "ours"]);
    let ours = f.git(&src, &["rev-parse", "HEAD"]);
    f.git(&src, &["push", "-q", mirror.to_str().unwrap(), "main"]);
    assert_eq!(
        f.ref_of(&mirror, "main").as_deref(),
        Some(ours.as_str()),
        "the mirror fast-forwards first..ours"
    );

    let run = carry_to_upstream(&f.cfg, &mirror, &url, None, &ours, "main").unwrap();
    let transition = parse_upstream_transition(&run.stdout, "main")
        .expect("the porcelain line names the upstream's transition");
    assert_eq!(
        transition.from.as_deref(),
        Some(theirs.as_str()),
        "the upstream moved from the THIRD PARTY's commit"
    );
    assert_ne!(
        transition.from.as_deref(),
        Some(first.as_str()),
        "the mirror's old tip is not what the upstream moved from"
    );
}

// ---------------------------------------------------------------------------
// Mirror creation is capped, atomic, and sweepable
// ---------------------------------------------------------------------------

#[test]
fn a_new_mirror_carries_gits_own_push_cap_in_its_config() {
    let f = Fixture::new();
    let cfg = GitConfig {
        max_push_bytes: 4096,
        ..f.cfg.clone()
    };
    let mirror = ensure_mirror(&cfg, &f.repo(), &f.hook_program()).unwrap();
    let read = run(
        &cfg,
        Some(&mirror),
        &["config", "--get", "receive.maxInputSize"],
        None,
        None,
    )
    .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&read.stdout).trim(),
        "4096",
        "git enforces the cap itself; we only declare it"
    );
}

#[test]
fn the_hook_install_is_atomic_and_leaves_no_partial_file() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    for _ in 0..5 {
        ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
        let installed = std::fs::read_to_string(mirror.join("hooks/update")).unwrap();
        // An EMPTY hook exits 0, which receive-pack reads as ALLOW — the one fail-open arm the
        // write-then-rename removes.
        assert!(
            !installed.is_empty() && installed.contains("git-update-hook"),
            "the hook is never observable half-written: {installed:?}"
        );
    }
    assert!(
        !mirror.join("hooks/update.staging").exists(),
        "the staging file is renamed, never left behind"
    );
}

#[test]
fn an_orphan_mirror_directory_ages_out() {
    // A mirror whose `git init` never finished has no `objects/`, and an objects-gated walk
    // would skip exactly those — so orphans must not be the one thing the sweep can never
    // reclaim.
    let f = Fixture::new();
    let orphan = f.cfg.mirror_dir.join("github/acme/half-made.git");
    std::fs::create_dir_all(&orphan).unwrap();
    let now = crate::util::now_epoch();
    touch_at(&orphan, now - 200 * 86_400);

    assert_eq!(purge_expired_mirrors(&f.cfg, now), 1);
    assert!(!orphan.exists(), "an orphan is reclaimable");
}

// ---------------------------------------------------------------------------
// The read refresh
// ---------------------------------------------------------------------------

/// `git clone --depth 1` through the broker came back an
/// EMPTY repository with exit 0.
///
/// Shallow negotiation was never involved. `--depth` implies `--single-branch`, and a
/// single-branch clone asks the SERVER which branch HEAD names. A mirror is `git init --bare`, so
/// its HEAD names git's compiled default (`refs/heads/master`), and the refresh writes only
/// `refs/heads/*` — on a `main` repository the mirror's HEAD stayed DANGLING, `upload-pack`
/// advertises no HEAD for a dangling symref, the client selected nothing to want, and the clone
/// came back empty. (A plain full clone fetched everything and then failed to check out, which is
/// how the same defect hid.)
#[test]
fn a_refresh_points_the_mirrors_head_at_the_upstreams_default_branch() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let (src, _oid) = f.source();
    let upstream = f.bare("upstream.git");
    f.git(&src, &["push", "-q", upstream.to_str().unwrap(), "main"]);
    // What a real forge advertises: HEAD is a symref at the repository's default branch.
    f.git(&upstream, &["symbolic-ref", "HEAD", "refs/heads/main"]);
    let url = format!("file://{}", upstream.display());

    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    // The state the bug was born in, pinned rather than inherited from the box's git defaults.
    run(
        &f.cfg,
        Some(&mirror),
        &["symbolic-ref", "HEAD", "refs/heads/master"],
        None,
        None,
    )
    .unwrap();

    refresh_from_upstream(&f.cfg, &mirror, &url, None).expect("the refresh succeeds");

    let head = run(&f.cfg, Some(&mirror), &["symbolic-ref", "HEAD"], None, None).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        "refs/heads/main",
        "a served mirror's HEAD names a branch it actually has"
    );

    // End to end, the exact invocation the usability trial ran: a shallow clone of the mirror has content.
    let out = f.root.join("shallow-clone");
    f.git(
        &f.root,
        &[
            "clone",
            "-q",
            "--depth",
            "1",
            &format!("file://{}", mirror.display()),
            out.to_str().unwrap(),
        ],
    );
    assert!(
        out.join("README.md").is_file(),
        "`git clone --depth 1` must not answer with an empty repository"
    );
}

/// The refresh runs on whatever git the box has at or above [`MIN_GIT_VERSION`], so its argv may
/// use only options that old. `git fetch --porcelain` is git 2.41, and an older git — Apple's
/// Command Line Tools git among them — answers `error: unknown option 'porcelain'` and fails the
/// refresh outright. What the receipt needs comes from the mirror's own refs instead, which is
/// plumbing every git in the supported range has.
#[test]
fn the_refresh_asks_git_for_nothing_newer_than_the_version_floor() {
    let argv = refresh_argv("file:///upstream.git");
    assert!(
        !argv.contains(&"--porcelain"),
        "`git fetch --porcelain` is newer than the {}.{} floor: {argv:?}",
        MIN_GIT_VERSION.0,
        MIN_GIT_VERSION.1
    );
    assert!(
        argv.contains(&"--prune"),
        "a branch deleted upstream stops being served here: {argv:?}"
    );
    assert!(
        argv.contains(&"+refs/heads/*:refs/heads/*"),
        "the mirror's branch namespace is forced equal to the upstream's: {argv:?}"
    );
}

/// A refresh's receipt is the mirror's refs before against the mirror's refs after: creations,
/// updates and prunes, and nothing at all for a hop that moved nothing.
#[test]
fn a_refresh_reports_every_ref_it_moved_and_nothing_it_left_alone() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let (src, first) = f.source();
    let upstream = f.bare("upstream.git");
    let url = format!("file://{}", upstream.display());
    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();

    // A ref the mirror does not have yet: no `from`, the upstream's tip as `to`.
    f.git(&src, &["push", "-q", upstream.to_str().unwrap(), "main"]);
    let seeded = refresh_from_upstream(&f.cfg, &mirror, &url, None).expect("the seeding refresh");
    assert_eq!(
        seeded.refs,
        vec![RefreshedRef {
            refname: "refs/heads/main".into(),
            from: None,
            to: Some(first.clone()),
        }]
    );
    assert_eq!((seeded.total, seeded.truncated), (1, false));

    // The upstream has not moved: a refresh that changed nothing reports nothing.
    let idle = refresh_from_upstream(&f.cfg, &mirror, &url, None).expect("an idle refresh");
    assert_eq!(idle, Refresh::default(), "an unchanged ref is not a change");

    // An advanced branch carries both tips; a branch new upstream is a creation in the same pass.
    std::fs::write(src.join("second.txt"), "second\n").unwrap();
    f.git(&src, &["add", "-A"]);
    f.git(&src, &["commit", "-q", "-m", "two"]);
    let second = f.git(&src, &["rev-parse", "HEAD"]);
    f.git(&src, &["branch", "side", &first]);
    f.git(
        &src,
        &["push", "-q", upstream.to_str().unwrap(), "main", "side"],
    );

    let moved = refresh_from_upstream(&f.cfg, &mirror, &url, None).expect("the second refresh");
    assert_eq!(
        moved.refs,
        vec![
            RefreshedRef {
                refname: "refs/heads/main".into(),
                from: Some(first.clone()),
                to: Some(second.clone()),
            },
            RefreshedRef {
                refname: "refs/heads/side".into(),
                from: None,
                to: Some(first.clone()),
            },
        ]
    );
    assert_eq!((moved.total, moved.truncated), (2, false));

    // A branch deleted upstream is PRUNED here: the tip it had, and no `to`.
    f.git(&upstream, &["update-ref", "-d", "refs/heads/side"]);
    let pruned = refresh_from_upstream(&f.cfg, &mirror, &url, None).expect("the pruning refresh");
    assert_eq!(
        pruned.refs,
        vec![RefreshedRef {
            refname: "refs/heads/side".into(),
            from: Some(first),
            to: None,
        }],
        "a pruned ref reports `to: null`, and the untouched branch reports nothing"
    );
    assert_eq!(f.ref_of(&mirror, "main").as_deref(), Some(second.as_str()));
    assert_eq!(
        f.ref_of(&mirror, "side"),
        None,
        "the mirror stopped serving it"
    );
}

/// A derived list is bounded: rows past the cap are COUNTED, not rendered, and an oversize refname
/// is counted rather than truncated into a name that is not the one that landed.
#[test]
fn a_huge_refresh_renders_a_bounded_list_and_says_so() {
    let oid = "a".repeat(40);
    let before = BTreeMap::new();
    let mut after: BTreeMap<String, String> = (0..MAX_CHANGED_ROWS + 5)
        .map(|i| (format!("refs/heads/b{i:04}"), oid.clone()))
        .collect();
    let long = format!("refs/heads/{}", "z".repeat(MAX_PATH_BYTES));
    after.insert(long.clone(), oid.clone());

    let refresh = diff_snapshots(&before, &after);
    assert_eq!(refresh.refs.len(), MAX_CHANGED_ROWS);
    assert_eq!(refresh.total, MAX_CHANGED_ROWS as u64 + 6);
    assert!(refresh.truncated);
    assert!(refresh.refs.iter().all(|r| r.refname != long));
}

/// The git a real user may be running: Apple's Command Line Tools git predates
/// `git fetch --porcelain` (git 2.41) and answers `error: unknown option 'porcelain'` — a refresh
/// that asks for it fails outright there. This git is that git for `fetch` and the real one for
/// everything else, so the whole hop runs on the real transport.
#[test]
fn a_git_without_fetch_porcelain_refreshes_end_to_end() {
    let f = Fixture::new();
    let older = executable(
        &f.root,
        "git-before-2.41",
        &format!(
            "#!/bin/sh\nif [ \"$1\" = fetch ]; then\n  for a in \"$@\"; do\n\
             \x20   if [ \"$a\" = --porcelain ]; then\n\
             \x20     echo \"error: unknown option \\`porcelain'\" >&2\n\
             \x20     exit 129\n\
             \x20   fi\n  done\nfi\nexec {SYSTEM_GIT} \"$@\"\n"
        ),
    );
    let cfg = f.cfg.clone().with_binary(&older);

    let hook = f.hook_program();
    let (src, first) = f.source();
    let upstream = f.bare("upstream.git");
    f.git(&src, &["push", "-q", upstream.to_str().unwrap(), "main"]);
    f.git(&upstream, &["symbolic-ref", "HEAD", "refs/heads/main"]);

    let mirror = ensure_mirror(&cfg, &f.repo(), &hook).unwrap();
    let refresh = refresh_from_upstream(
        &cfg,
        &mirror,
        &format!("file://{}", upstream.display()),
        None,
    )
    .expect("a git without `fetch --porcelain` still refreshes");

    assert_eq!(
        refresh.refs,
        vec![RefreshedRef {
            refname: "refs/heads/main".into(),
            from: None,
            to: Some(first.clone()),
        }],
        "and the receipt is the same one a newer git produces"
    );
    assert_eq!(f.ref_of(&mirror, "main"), Some(first));
}

/// A genuinely EMPTY upstream still refreshes: it has no branches, so its dangling HEAD is the
/// truth, and "you cloned an empty repository" is the right answer rather than a refusal.
#[test]
fn an_empty_upstream_refreshes_without_a_head_to_align() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let upstream = f.bare("upstream.git");
    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    refresh_from_upstream(
        &f.cfg,
        &mirror,
        &format!("file://{}", upstream.display()),
        None,
    )
    .expect("an empty upstream is not an error");
}

/// The mirror COPIES the upstream and never invents. An upstream that advertises no HEAD of its own
/// — a bare repo nobody set a default branch on — leaves the mirror's HEAD alone, so the mirror
/// behaves for a clone exactly as that upstream does. The defect was the mirror DISAGREEING with its
/// upstream; reproducing an upstream's own headlessness is not that, and refusing it would make a
/// repository unreachable through the broker that is reachable without it.
#[test]
fn a_headless_upstream_leaves_the_mirrors_head_alone() {
    let f = Fixture::new();
    let hook = f.hook_program();
    let (src, _oid) = f.source();
    let upstream = f.bare("upstream.git");
    f.git(&src, &["push", "-q", upstream.to_str().unwrap(), "main"]);
    // An upstream whose own HEAD is dangling advertises no default branch to copy.
    f.git(&upstream, &["symbolic-ref", "HEAD", "refs/heads/nowhere"]);

    let mirror = ensure_mirror(&f.cfg, &f.repo(), &hook).unwrap();
    run(
        &f.cfg,
        Some(&mirror),
        &["symbolic-ref", "HEAD", "refs/heads/master"],
        None,
        None,
    )
    .unwrap();

    refresh_from_upstream(
        &f.cfg,
        &mirror,
        &format!("file://{}", upstream.display()),
        None,
    )
    .expect("an upstream with nothing to copy is not an error");

    let head = run(&f.cfg, Some(&mirror), &["symbolic-ref", "HEAD"], None, None).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&head.stdout).trim(),
        "refs/heads/master",
        "with no upstream default to copy, the mirror keeps the HEAD it had"
    );
}

// ---------------------------------------------------------------------------
// The credentialed hop is CREDENTIALED, and says so when the upstream refuses it
//
// A `git clone` through the plane once came back:
//
//   provider error: the upstream refresh failed: fatal: could not read Username for
//   'https://github.com': terminal prompts disabled; cermet: refusing to serve a stale mirror
//
// The refusal direction was right and the mirror stayed honest, but the WORDS are git describing
// its own fallback, and they read as "no credential was sent". They cost that run its diagnosis:
// the actual cause was a vaulted token the upstream rejected. The daemon knows which of those two
// it is — it knows whether it attached a credential — so the refusal now says so.
//
// The tests below need a git that fails on demand and a git that records its own environment.
// Every other upstream test here runs against a `file://` upstream, where `http.<url>.extraHeader`
// is inert, so nothing in this suite could previously tell an attached credential from a missing
// one on ANY upstream path. These two close that.
// ---------------------------------------------------------------------------

/// Write `script` as an executable stand-in at `root/name`, ready to run.
fn executable(root: &Path, name: &str, script: &str) -> PathBuf {
    let path = root.join(name);
    std::fs::write(&path, script).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    // A test spawning a child on another thread inherits this file's write end across the fork, and
    // the kernel then refuses to exec the file (ETXTBSY) until that child exits. Wait it out here,
    // where it is a helper detail, instead of letting it surface as a bogus "git is not usable".
    for _ in 0..200 {
        match Command::new(&path).arg("--version").output() {
            Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                std::thread::sleep(Duration::from_millis(10))
            }
            _ => break,
        }
    }
    path
}

/// A stand-in `git`: it satisfies the version floor and answers the local ref read of an empty
/// repository, then runs `body` for every other invocation — the one that reaches the upstream.
/// Each one gets its own path because `usable` caches its verdict per binary.
fn fake_git(root: &Path, name: &str, body: &str) -> PathBuf {
    executable(
        root,
        name,
        &format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'git version 2.99.0'; exit 0; fi\n\
             if [ \"$1\" = for-each-ref ]; then exit 0; fi\n{body}\n"
        ),
    )
}

/// GitHub's own answer when it rejects what we sent: a 401, after which git falls back to asking
/// for a username it has no terminal to ask on. Byte-for-byte what the fresh-box run recorded.
const REJECTED_STDERR: &str =
    "fatal: could not read Username for 'https://github.com': terminal prompts disabled";

#[test]
fn an_upstream_that_rejects_the_vaulted_credential_says_that_instead_of_gits_prompt_wording() {
    let f = Fixture::new();
    std::fs::create_dir_all(&f.cfg.mirror_dir).unwrap();
    let binary = fake_git(
        &f.root,
        "git-rejects",
        &format!("echo \"{REJECTED_STDERR}\" >&2\nexit 128"),
    );
    let cfg = f.cfg.clone().with_binary(&binary);
    let url = "https://github.invalid/acme/website.git";
    let cred = GitCredential {
        url: url.into(),
        header: "Authorization: Basic c2VjcmV0".into(),
    };

    let error = refresh_from_upstream(&cfg, &f.cfg.mirror_dir, url, Some(&cred))
        .expect_err("a refused refresh is a refusal, never a stale serve");
    let text = format!("{error}");
    assert!(
        text.contains("did not accept the vaulted credential"),
        "the refusal names what actually happened:\n{text}"
    );
    assert!(
        text.contains("expired, revoked, or without access"),
        "and what to do about it:\n{text}"
    );
    assert!(
        text.contains("could not read Username"),
        "git's own words are kept, never replaced:\n{text}"
    );
    assert!(
        !text.contains("c2VjcmV0"),
        "and the credential itself is never in the message:\n{text}"
    );
    // The same fact, TYPED: the refusal carries the class so the terminal event records evidence
    // rather than this sentence. `provider_auth_refused` is the one an operator acts on.
    assert_eq!(
        error.effect_failure_class(),
        Some(EffectFailureClass::ProviderAuthRefused),
        "the refusal carries its class:\n{text}"
    );
}

#[test]
fn a_push_the_upstream_refuses_on_credentials_reads_the_same_way() {
    let f = Fixture::new();
    std::fs::create_dir_all(&f.cfg.mirror_dir).unwrap();
    let binary = fake_git(
        &f.root,
        "git-rejects-push",
        &format!("echo \"{REJECTED_STDERR}\" >&2\nexit 128"),
    );
    let cfg = f.cfg.clone().with_binary(&binary);
    let url = "https://github.invalid/acme/website.git";
    let cred = GitCredential {
        url: url.into(),
        header: "Authorization: Basic c2VjcmV0".into(),
    };
    let error = carry_to_upstream(
        &cfg,
        &f.cfg.mirror_dir,
        url,
        Some(&cred),
        &"a".repeat(40),
        "main",
    )
    .expect_err("a refused push is a refusal");
    let text = format!("{error}");
    assert!(
        text.contains("did not accept the vaulted credential"),
        "the hop's refusal reads the same way in both directions:\n{text}"
    );
    assert_eq!(
        error.effect_failure_class(),
        Some(EffectFailureClass::ProviderAuthRefused),
        "in both directions, including the class:\n{text}"
    );
}

#[test]
fn an_uncredentialed_or_unrelated_failure_never_blames_a_credential() {
    let f = Fixture::new();
    std::fs::create_dir_all(&f.cfg.mirror_dir).unwrap();
    let url = "https://github.invalid/acme/website.git";

    // No credential was attached, so an auth-shaped failure means exactly what git says.
    let binary = fake_git(
        &f.root,
        "git-rejects-anon",
        &format!("echo \"{REJECTED_STDERR}\" >&2\nexit 128"),
    );
    let anon = refresh_from_upstream(
        &f.cfg.clone().with_binary(&binary),
        &f.cfg.mirror_dir,
        url,
        None,
    )
    .expect_err("still a refusal");
    assert!(
        !format!("{anon}").contains("vaulted credential"),
        "nothing was vaulted into that invocation:\n{anon}"
    );
    // The residual, not a guess: git says the same words for a dead network, a missing repository
    // and a non-fast-forward, and the seam refuses to mine that prose for a finer class.
    assert_eq!(
        anon.effect_failure_class(),
        Some(EffectFailureClass::Failed),
        "an uncredentialed refusal classifies as the residual:\n{anon}"
    );

    // A credential WAS attached, but the upstream never got far enough to judge it.
    let unreachable = fake_git(
        &f.root,
        "git-unreachable",
        "echo 'fatal: unable to access: Could not resolve host: github.invalid' >&2\nexit 128",
    );
    let cred = GitCredential {
        url: url.into(),
        header: "Authorization: Basic c2VjcmV0".into(),
    };
    let error = refresh_from_upstream(
        &f.cfg.clone().with_binary(&unreachable),
        &f.cfg.mirror_dir,
        url,
        Some(&cred),
    )
    .expect_err("still a refusal");
    assert!(
        !format!("{error}").contains("vaulted credential"),
        "an unreachable host is not a rejected credential:\n{error}"
    );
    assert!(
        format!("{error}").contains("Could not resolve host"),
        "{error}"
    );
    assert_eq!(
        error.effect_failure_class(),
        Some(EffectFailureClass::Failed),
        "an unreachable host the seam cannot type is the residual:\n{error}"
    );
}

/// The standing guard. EVERY git invocation that names the upstream carries the credential channel,
/// scoped to that exact URL — the property a `file://` upstream can never test, and the one whose
/// absence would produce a refusal indistinguishable from the one above.
#[test]
fn every_upstream_invocation_carries_the_credential_scoped_to_that_url() {
    let f = Fixture::new();
    std::fs::create_dir_all(&f.cfg.mirror_dir).unwrap();
    // `hermetic_command` clears the environment and sets HOME to the mirror dir, so that is the one
    // place the recorder can be told to write to.
    let binary = fake_git(
        &f.root,
        "git-recorder",
        "{ printf 'ARGV'; for a in \"$@\"; do printf ' %s' \"$a\"; done; \
         printf '\\nKEY0=%s\\nVALUE0=%s\\n' \"${GIT_CONFIG_KEY_0-}\" \"${GIT_CONFIG_VALUE_0-}\"; } \
         >> \"$HOME/invocations.log\"\nexit 0",
    );
    let cfg = f.cfg.clone().with_binary(&binary);
    let url = "https://github.invalid/acme/website.git";
    let cred = GitCredential {
        url: url.into(),
        header: "Authorization: Basic c2VjcmV0".into(),
    };
    let mirror = f.cfg.mirror_dir.clone();

    // The three ways this daemon ever touches an upstream. The first is the one a virgin mirror
    // runs — mirror creation and mirror refresh are the same call, so this covers both.
    refresh_from_upstream(&cfg, &mirror, url, Some(&cred)).expect("refresh");
    carry_to_upstream(&cfg, &mirror, url, Some(&cred), &"a".repeat(40), "main").expect("push");
    upstream_head_branch(&cfg, url, Some(&cred)).expect("ls-remote");

    let log = std::fs::read_to_string(mirror.join("invocations.log")).expect("the recorder ran");
    let mut upstream_invocations = 0;
    for record in log.split("ARGV").filter(|r| !r.trim().is_empty()) {
        let argv = record.lines().next().unwrap_or_default();
        if !argv.contains(url) {
            continue;
        }
        upstream_invocations += 1;
        assert!(
            record.contains(&format!("KEY0=http.{url}.extraHeader")),
            "an upstream invocation ran with no credential scope:\n{record}"
        );
        assert!(
            record.contains(&format!("VALUE0={}", cred.header)),
            "an upstream invocation ran with an empty credential:\n{record}"
        );
    }
    assert_eq!(
        upstream_invocations, 3,
        "fetch, push and ls-remote each reached the upstream exactly once:\n{log}"
    );
}
