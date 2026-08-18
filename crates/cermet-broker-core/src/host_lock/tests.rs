use super::*;
use std::os::unix::ffi::OsStrExt;
use tempfile::tempdir;

fn mode_of(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
}

// ---- acquire_hardened_lock ----

#[test]
fn lock_is_exclusive_and_self_heals() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("host.lock");
    let first = acquire_hardened_lock(&p)
        .expect("io")
        .expect("first acquires");
    assert!(
        acquire_hardened_lock(&p).expect("io").is_none(),
        "a second writer is refused while the first holds the lock"
    );
    drop(first);
    assert!(
        acquire_hardened_lock(&p).expect("io").is_some(),
        "a released lock is re-acquirable (crash self-heal)"
    );
}

#[test]
fn lock_creates_the_file_0600() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("host.lock");
    let _g = acquire_hardened_lock(&p).expect("io").expect("acquires");
    assert_eq!(mode_of(&p), 0o600, "the lock file is created owner-only");
}

#[test]
fn symlink_lock_path_fails_closed() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("target");
    std::fs::write(&target, b"x").unwrap();
    let link = dir.path().join("host.lock");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        acquire_hardened_lock(&link).is_err(),
        "a symlink at the lock path must fail closed (O_NOFOLLOW), not follow to the target"
    );
}

#[test]
fn fifo_lock_path_fails_closed_without_hanging() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("host.lock");
    let cpath = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { nix::libc::mkfifo(cpath.as_ptr(), 0o600 as nix::libc::mode_t) };
    assert_eq!(rc, 0, "mkfifo failed: {}", io::Error::last_os_error());
    // With O_NONBLOCK this returns immediately (ENXIO) instead of blocking for a reader.
    assert!(
        acquire_hardened_lock(&p).is_err(),
        "a FIFO at the lock path must fail closed without hanging"
    );
}

#[test]
fn directory_lock_path_fails_closed() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("host.lock");
    std::fs::create_dir(&p).unwrap();
    assert!(
        acquire_hardened_lock(&p).is_err(),
        "a directory at the lock path must fail closed"
    );
}

fn mkfifo_at(p: &Path) {
    let cpath = std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    let rc = unsafe { nix::libc::mkfifo(cpath.as_ptr(), 0o600 as nix::libc::mode_t) };
    assert_eq!(rc, 0, "mkfifo failed: {}", io::Error::last_os_error());
}

#[test]
fn validate_regular_owned_refuses_a_non_regular_fd() {
    // This guard now runs on BOTH lock branches (incl. busy/WouldBlock), so a foreign-held or
    // non-regular host.lock is refused, not treated as a legitimate live host. Same-uid we can
    // exercise the non-regular half directly: a FIFO fd is rejected.
    let dir = tempdir().unwrap();
    let fifo = dir.path().join("f");
    mkfifo_at(&fifo);
    // Open the read-end non-blocking so the open itself does not block waiting for a writer.
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NONBLOCK)
        .open(&fifo)
        .expect("open fifo read-end");
    assert!(
        validate_regular_owned(&f).is_err(),
        "a non-regular fd (FIFO) must be refused"
    );
}

#[test]
fn read_nofollow_refuses_a_fifo_without_hanging() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("host.json");
    mkfifo_at(&p);
    // O_NONBLOCK + the fstat reject means this returns Err immediately rather than blocking on
    // a FIFO open/read; the test simply completing (no timeout) is the no-hang proof.
    assert!(
        read_nofollow(&p).is_err(),
        "a FIFO at host.json must fail closed without hanging"
    );
}

#[test]
fn read_nofollow_bounds_the_read() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("host.json");
    std::fs::write(&p, vec![b'x'; MAX_HOST_JSON as usize + 4096]).unwrap();
    let got = read_nofollow(&p).expect("reads a regular file");
    assert_eq!(
        got.len(),
        MAX_HOST_JSON as usize,
        "the read is bounded to MAX_HOST_JSON"
    );
}

// ---- read_authority_file ----

#[test]
fn read_authority_file_reads_an_owned_regular_file() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("policy.yaml");
    std::fs::write(&p, b"version: 1\n").unwrap();
    // Pin 0600 so the read succeeds regardless of the test runner's umask (the write-bit guard
    // below would reject a 0666 file under a permissive umask).
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(read_authority_file(&p).unwrap(), b"version: 1\n");
}

#[test]
fn read_authority_file_refuses_a_symlink() {
    // The sharp case: a planted symlink at policy.yaml pointing at attacker-chosen bytes
    // must fail closed (O_NOFOLLOW), not be followed and loaded as authority.
    let dir = tempdir().unwrap();
    let target = dir.path().join("attacker-policy.yaml");
    std::fs::write(&target, b"allow: everything\n").unwrap();
    let link = dir.path().join("policy.yaml");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let err = read_authority_file(&link).expect_err("a symlinked authority file must fail closed");
    assert_ne!(
        err.kind(),
        ErrorKind::NotFound,
        "a present-but-symlinked file is an error the caller must fail closed on, NOT NotFound \
             (which would let it fall back to a permissive default)"
    );
}

#[test]
fn read_authority_file_refuses_a_fifo_without_hanging() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("policy.yaml");
    mkfifo_at(&p);
    // O_NOFOLLOW|O_NONBLOCK + the fstat regular-file reject means this returns Err immediately
    // rather than blocking on the FIFO open; the test completing is the no-hang proof.
    assert!(
        read_authority_file(&p).is_err(),
        "a FIFO at the authority path must fail closed without hanging"
    );
}

#[test]
fn read_authority_file_refuses_an_over_cap_file() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("principals.json");
    std::fs::write(&p, vec![b'x'; MAX_AUTHORITY_FILE as usize + 1]).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    let err = read_authority_file(&p).expect_err("an over-cap file must be refused");
    assert_eq!(
        err.kind(),
        ErrorKind::InvalidData,
        "an over-cap authority file is refused, not silently truncated"
    );
}

#[test]
fn read_authority_file_accepts_an_exactly_cap_file() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("policy.yaml");
    std::fs::write(&p, vec![b'x'; MAX_AUTHORITY_FILE as usize]).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        read_authority_file(&p).unwrap().len(),
        MAX_AUTHORITY_FILE as usize,
        "a file exactly at the cap is accepted whole"
    );
}

#[test]
fn read_authority_file_refuses_a_group_or_world_writable_file() {
    // An owner-owned-but-writable authority file can be rewritten by another uid (group or
    // other), so the owner check is insufficient — reject any group/other WRITE bit.
    let dir = tempdir().unwrap();
    let g = dir.path().join("policy.yaml");
    std::fs::write(&g, b"version: 1\n").unwrap();
    std::fs::set_permissions(&g, std::fs::Permissions::from_mode(0o664)).unwrap();
    assert!(
        read_authority_file(&g).is_err(),
        "a group-writable (0664) authority file must fail closed"
    );

    let o = dir.path().join("principals.json");
    std::fs::write(&o, b"{}").unwrap();
    std::fs::set_permissions(&o, std::fs::Permissions::from_mode(0o606)).unwrap();
    assert!(
        read_authority_file(&o).is_err(),
        "an other-writable (0606) authority file must fail closed"
    );
}

#[test]
fn read_authority_file_accepts_world_readable_not_writable() {
    // 0644: readable by all but writable only by the owner — fine, policy is not a secret. Only
    // WRITE bits are the threat (a different uid rewriting the authority).
    let dir = tempdir().unwrap();
    let p = dir.path().join("policy.yaml");
    std::fs::write(&p, b"version: 1\n").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(read_authority_file(&p).unwrap(), b"version: 1\n");
}

#[test]
fn read_authority_file_surfaces_notfound_distinctly() {
    // A genuinely-absent file must be NotFound so the caller can fall back to a built-in default
    // (policy) or an empty store (principals) — distinct from the fail-closed foreign/symlink case.
    let dir = tempdir().unwrap();
    let p = dir.path().join("does-not-exist.yaml");
    let err = read_authority_file(&p).expect_err("a missing file is an error");
    assert_eq!(
        err.kind(),
        ErrorKind::NotFound,
        "absence is reported as NotFound"
    );
}

// ---- harden_dir ----

#[test]
fn harden_dir_creates_missing_0700() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    harden_dir(&home).expect("creates");
    assert!(home.is_dir());
    assert_eq!(mode_of(&home), 0o700, "a created home is owner-only");
}

#[test]
fn harden_dir_retightens_a_loose_owned_dir() {
    let dir = tempdir().unwrap();
    let home = dir.path().join("home");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o777)).unwrap();
    harden_dir(&home).expect("retightens");
    assert_eq!(
        mode_of(&home),
        0o700,
        "a loose owned home is retightened to 0700"
    );
}

#[test]
fn harden_dir_refuses_a_symlink() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("real");
    std::fs::create_dir(&target).unwrap();
    let link = dir.path().join("home");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        harden_dir(&link).is_err(),
        "a symlinked home must be refused (symlink_metadata does not follow)"
    );
}

#[test]
fn harden_dir_refuses_a_non_directory() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("home");
    std::fs::write(&p, b"not a dir").unwrap();
    assert!(
        harden_dir(&p).is_err(),
        "a regular file at the home path must be refused"
    );
}

// ---- harden_runtime_dir ----

// Same-uid the test can only chmod (not chgrp to a foreign group), so we pin owner==geteuid and
// approvers_gid==the dir's own gid, then mutate one condition at a time to drive each refusal.
fn make_runtime_dir(parent: &Path, mode: u32) -> (std::path::PathBuf, u32, u32) {
    let d = parent.join("run");
    std::fs::create_dir(&d).unwrap();
    // set_permissions honors the setgid/sticky bits in the 12-bit mode.
    std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode)).unwrap();
    let meta = std::fs::symlink_metadata(&d).unwrap();
    (d, meta.uid(), meta.gid())
}

#[test]
fn harden_runtime_dir_accepts_2711_owner_approvers() {
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o2711);
    harden_runtime_dir(&d, uid, gid).expect("a 2711 owner:approvers dir passes");
}

#[test]
fn harden_runtime_dir_does_not_mutate_the_dir() {
    // Assert-only: a passing call must NOT chmod/force-0700 the dir (unlike harden_dir).
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o2711);
    harden_runtime_dir(&d, uid, gid).expect("passes");
    let mode = std::fs::symlink_metadata(&d).unwrap().permissions().mode() & 0o7777;
    assert_eq!(
        mode, 0o2711,
        "harden_runtime_dir must not modify the runtime dir's mode"
    );
}

#[test]
fn harden_runtime_dir_refuses_0700() {
    // The existing 0700 harden_dir layout must NOT satisfy the runtime-dir contract: no setgid,
    // no world-traversal — a cross-uid approver could not reach ctl.sock.
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o0700);
    assert!(
        harden_runtime_dir(&d, uid, gid).is_err(),
        "a 0700 dir must fail closed (no setgid, not world-traversable)"
    );
}

#[test]
fn harden_runtime_dir_refuses_missing_setgid() {
    // 0711 (world-traversable, not writable) but WITHOUT the setgid bit: bound sockets would not
    // inherit the approvers group.
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o0711);
    assert!(
        harden_runtime_dir(&d, uid, gid).is_err(),
        "a dir missing the setgid bit must fail closed"
    );
}

#[test]
fn harden_runtime_dir_refuses_world_writable() {
    // 2717: setgid + world-traversable but world-WRITABLE — a foreign principal could plant/swap
    // the socket inode.
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o2717);
    assert!(
        harden_runtime_dir(&d, uid, gid).is_err(),
        "a world-writable runtime dir must fail closed"
    );
}

#[test]
fn harden_runtime_dir_refuses_group_writable() {
    // 2731: setgid + world-traversable but GROUP-writable — also refused.
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o2731);
    assert!(
        harden_runtime_dir(&d, uid, gid).is_err(),
        "a group-writable runtime dir must fail closed"
    );
}

#[test]
fn harden_runtime_dir_refuses_not_world_traversable() {
    // 2710: setgid + owner-only, but NOT world-traversable (other-x clear) — a cross-uid approver
    // could not --x into the dir to reach ctl.sock.
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o2710);
    assert!(
        harden_runtime_dir(&d, uid, gid).is_err(),
        "a non-world-traversable runtime dir must fail closed"
    );
}

#[test]
fn harden_runtime_dir_refuses_2701_group_loses_traversal() {
    // 2701 = setgid + world-traversable, but the GROUP loses --x (group-execute clear).
    // The dir's group IS cermet-approvers, so a 2701 dir strands the approver class — they
    // cannot traverse to ctl.sock. Only bit-exact 2711 (group --x set) is accepted.
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o2701);
    assert!(
        harden_runtime_dir(&d, uid, gid).is_err(),
        "a 2701 dir (group loses --x) must fail closed — the approvers group would be stranded"
    );
}

#[test]
fn harden_runtime_dir_refuses_2755_world_listable() {
    // 2755 = setgid + world read+traverse. World-LISTABLE (other-r set) leaks the
    // socket inventory to every local uid; only bit-exact 2711 is accepted.
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o2755);
    assert!(
        harden_runtime_dir(&d, uid, gid).is_err(),
        "a 2755 dir (world-listable) must fail closed — only bit-exact 2711 passes"
    );
}

#[test]
fn harden_runtime_dir_refuses_3711_stray_sticky_bit() {
    // 3711 = 2711 + the sticky bit (01000). A stray special bit is not the locked
    // layout; bit-exactness rejects it.
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o3711);
    assert!(
        harden_runtime_dir(&d, uid, gid).is_err(),
        "a 3711 dir (stray sticky bit) must fail closed — only bit-exact 2711 passes"
    );
}

#[test]
fn harden_runtime_dir_refuses_6711_stray_setuid_bit() {
    // 6711 = 2711 + the setuid bit (04000). A stray setuid bit is not the locked
    // layout; bit-exactness rejects it.
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o6711);
    assert!(
        harden_runtime_dir(&d, uid, gid).is_err(),
        "a 6711 dir (stray setuid bit) must fail closed — only bit-exact 2711 passes"
    );
}

#[test]
fn harden_runtime_dir_refuses_wrong_owner() {
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o2711);
    assert!(
        harden_runtime_dir(&d, uid + 1, gid).is_err(),
        "a dir owned by a different uid than expected must fail closed"
    );
}

#[test]
fn harden_runtime_dir_refuses_wrong_group() {
    let dir = tempdir().unwrap();
    let (d, uid, gid) = make_runtime_dir(dir.path(), 0o2711);
    assert!(
        harden_runtime_dir(&d, uid, gid + 1).is_err(),
        "a dir grouped to a different gid than the approvers gid must fail closed"
    );
}

#[test]
fn harden_runtime_dir_refuses_a_symlink() {
    let dir = tempdir().unwrap();
    let (target, uid, gid) = make_runtime_dir(dir.path(), 0o2711);
    let link = dir.path().join("run-link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        harden_runtime_dir(&link, uid, gid).is_err(),
        "a symlinked runtime dir must be refused (symlink_metadata does not follow)"
    );
}

#[test]
fn harden_runtime_dir_refuses_a_non_directory() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("not-a-dir");
    std::fs::write(&p, b"x").unwrap();
    let meta = std::fs::symlink_metadata(&p).unwrap();
    assert!(
        harden_runtime_dir(&p, meta.uid(), meta.gid()).is_err(),
        "a regular file at the runtime-dir path must be refused"
    );
}

#[test]
fn harden_runtime_dir_errors_on_missing_path() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("does-not-exist");
    assert!(
        harden_runtime_dir(&p, 0, 0).is_err(),
        "a missing runtime dir must surface an error (assert-only: it never creates)"
    );
}

// ---- write_replace_nofollow / read_nofollow ----

#[test]
fn write_replace_creates_fresh_0600() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("host.json");
    write_replace_nofollow(&p, b"hello", 0o600).expect("writes");
    assert_eq!(std::fs::read(&p).unwrap(), b"hello");
    assert_eq!(mode_of(&p), 0o600);
}

#[test]
fn write_replace_replaces_an_owned_regular_file_with_a_fresh_mode() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("host.json");
    std::fs::write(&p, b"old").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    write_replace_nofollow(&p, b"new", 0o600).expect("replaces");
    assert_eq!(std::fs::read(&p).unwrap(), b"new");
    assert_eq!(
        mode_of(&p),
        0o600,
        "the replacement has the fresh mode, not the stale 0644"
    );
}

#[test]
fn write_replace_refuses_a_symlink_and_does_not_touch_the_target() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("victim");
    std::fs::write(&target, b"precious").unwrap();
    let link = dir.path().join("host.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        write_replace_nofollow(&link, b"attacker", 0o600).is_err(),
        "a symlink at host.json must fail closed"
    );
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"precious",
        "the symlink target must NOT be overwritten"
    );
}

#[test]
fn read_secret_nofollow_refuses_group_or_world_readable() {
    // The master-key reader must refuse a group/world-READABLE key file (0644/0640) —
    // owner-owned is NOT enough for secret material; a 0644 cermet.key is world-readable and
    // exactly the misconfiguration the DiD layer must catch. A 0600/0400 file still reads.
    let dir = tempdir().unwrap();
    let ok = dir.path().join("cermet.key");
    std::fs::write(&ok, b"secret").unwrap();
    std::fs::set_permissions(&ok, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        read_secret_nofollow(&ok).unwrap(),
        b"secret",
        "a 0600 owner-only secret file must read"
    );

    let world = dir.path().join("world.key");
    std::fs::write(&world, b"secret").unwrap();
    std::fs::set_permissions(&world, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(
        read_secret_nofollow(&world).is_err(),
        "a 0644 world-readable secret file must fail closed"
    );

    let group = dir.path().join("group.key");
    std::fs::write(&group, b"secret").unwrap();
    std::fs::set_permissions(&group, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(
        read_secret_nofollow(&group).is_err(),
        "a 0640 group-readable secret file must fail closed"
    );

    // The check must be SYMMETRIC — a group/world-WRITABLE key file is a
    // key-substitution vector squarely in this DiD layer's threat model, so refuse it too even
    // though it is not readable (0602 = other-w only, 0620 = group-w only).
    let ww = dir.path().join("world_w.key");
    std::fs::write(&ww, b"secret").unwrap();
    std::fs::set_permissions(&ww, std::fs::Permissions::from_mode(0o602)).unwrap();
    assert!(
        read_secret_nofollow(&ww).is_err(),
        "a 0602 world-writable secret file must fail closed (key-substitution vector)"
    );

    let gw = dir.path().join("group_w.key");
    std::fs::write(&gw, b"secret").unwrap();
    std::fs::set_permissions(&gw, std::fs::Permissions::from_mode(0o620)).unwrap();
    assert!(
        read_secret_nofollow(&gw).is_err(),
        "a 0620 group-writable secret file must fail closed (key-substitution vector)"
    );

    // O_NOFOLLOW still applies to the secret reader.
    let target = dir.path().join("target.key");
    std::fs::write(&target, b"leak").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = dir.path().join("link.key");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        read_secret_nofollow(&link).is_err(),
        "a symlinked secret file must fail closed (O_NOFOLLOW)"
    );
}

#[test]
fn read_nofollow_reads_a_regular_file_and_refuses_a_symlink() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("host.json");
    std::fs::write(&p, b"data").unwrap();
    assert_eq!(read_nofollow(&p).unwrap(), b"data");

    let target = dir.path().join("secret");
    std::fs::write(&target, b"leak").unwrap();
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        read_nofollow(&link).is_err(),
        "a symlink must fail closed on read"
    );
}

// ---- harden_file_0600 ----

#[test]
fn harden_file_retightens_a_loose_owned_file_to_0600() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    std::fs::write(&p, b"secret-db").unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
    harden_file_0600(&p).expect("retightens an owned regular file");
    assert_eq!(
        mode_of(&p),
        0o600,
        "a 0644 owned file is retightened to 0600"
    );
    assert_eq!(
        std::fs::read(&p).unwrap(),
        b"secret-db",
        "hardening must not alter the file's bytes"
    );
}

#[test]
fn harden_file_refuses_a_symlink_and_does_not_touch_the_target() {
    let dir = tempdir().unwrap();
    let target = dir.path().join("victim");
    std::fs::write(&target, b"precious").unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
    let link = dir.path().join("master.key");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        harden_file_0600(&link).is_err(),
        "a symlink at the key/db path must fail closed (O_NOFOLLOW), not chmod the target"
    );
    assert_eq!(
        mode_of(&target),
        0o644,
        "the symlink target's mode must NOT be tightened through the link"
    );
}

#[test]
fn harden_file_refuses_a_fifo_without_hanging() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    mkfifo_at(&p);
    // O_NOFOLLOW|O_NONBLOCK + the fstat regular-file reject means this returns Err immediately
    // rather than blocking on the FIFO open; the test simply completing is the no-hang proof.
    assert!(
        harden_file_0600(&p).is_err(),
        "a non-regular file (FIFO) must fail closed without hanging"
    );
}

#[test]
fn harden_file_refuses_a_directory() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("vault.db");
    std::fs::create_dir(&p).unwrap();
    assert!(
        harden_file_0600(&p).is_err(),
        "a directory at the db path must fail closed (not a regular file)"
    );
}

#[test]
fn harden_file_errors_on_missing_path() {
    let dir = tempdir().unwrap();
    let p = dir.path().join("does-not-exist.key");
    assert!(
        harden_file_0600(&p).is_err(),
        "a missing path must surface an error (caller hardens only existing inodes)"
    );
}

// The foreign-owned branch (uid != geteuid) fails closed but is not exercised same-uid:
// it needs a privileged second-uid harness (the deferred cross-uid track), like the other
// foreign-uid branches in this module.

// ---- set_umask_0077 ----

#[test]
fn set_umask_0077_tightens_new_file_creation() {
    // Serialized: umask is process-global, so we set, create, then restore atomically here.
    let prev = set_umask_0077();
    let dir = tempdir().unwrap();
    let p = dir.path().join("fresh-wal");
    // Request 0666; the 0077 umask must strip group+other so the inode lands 0600.
    let _f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o666)
        .open(&p)
        .expect("create");
    let got = mode_of(&p);
    // Restore the prior umask before asserting so a failure does not leak global state.
    unsafe { nix::libc::umask(prev) };
    assert_eq!(
        got, 0o600,
        "with umask 0077, a 0666-requested file is created 0600 (group/other stripped)"
    );
}

#[test]
fn set_umask_0077_returns_the_previous_mask() {
    // umask() returns the prior value; setting twice must report 0o077 the second time.
    let first = set_umask_0077();
    let second = set_umask_0077();
    // Restore whatever was there before this test ran.
    unsafe { nix::libc::umask(first) };
    assert_eq!(
        second, 0o077,
        "the second call observes the 0077 the first call installed"
    );
}

// --- $CREDENTIALS_DIRECTORY directory validation (Linux DiD) ------------------

#[test]
fn validate_credentials_dir_accepts_owned_0700_dir() {
    // The systemd-managed credential tmpfs is a 0700 dir owned by the service uid — the
    // happy path must pass so the daemon can read cermet.key out of it.
    let dir = tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        validate_credentials_dir(dir.path()).is_ok(),
        "a 0700 owner-owned credentials dir must validate"
    );
}

#[test]
fn validate_credentials_dir_refuses_group_or_world_writable() {
    // A group/world-writable credentials dir lets another principal plant or swap cermet.key,
    // defeating the O_NOFOLLOW read of the file — refuse it (fail closed).
    let dir = tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
    assert!(
        validate_credentials_dir(dir.path()).is_err(),
        "a group-writable (0770) credentials dir must fail closed"
    );
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o707)).unwrap();
    assert!(
        validate_credentials_dir(dir.path()).is_err(),
        "a world-writable (0707) credentials dir must fail closed"
    );
}

#[test]
fn validate_credentials_dir_refuses_group_or_world_readable() {
    // systemd provisions the credentials dir 0700 root-private; a group/world-READABLE
    // dir (0755/0705) is the misconfigured launch context this DiD layer exists to catch, so it
    // must fail closed even though a readable dir alone leaks only the listing, not cermet.key's
    // contents — refuse it defensively.
    let dir = tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
    assert!(
        validate_credentials_dir(dir.path()).is_err(),
        "a group-readable (0750) credentials dir must fail closed"
    );
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o705)).unwrap();
    assert!(
        validate_credentials_dir(dir.path()).is_err(),
        "a world-readable (0705) credentials dir must fail closed"
    );
    // restore for cleanup
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn validate_credentials_dir_refuses_a_symlinked_dir() {
    // O_NOFOLLOW: a symlink AT the credentials dir path (redirecting to an attacker-owned dir)
    // must fail closed rather than follow.
    let dir = tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
    let link = dir.path().join("creds");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(
        validate_credentials_dir(&link).is_err(),
        "a symlinked credentials dir must fail closed (O_NOFOLLOW)"
    );
}

#[test]
fn validate_credentials_dir_refuses_a_non_directory() {
    // O_DIRECTORY: a regular file where a dir is expected yields ENOTDIR — refuse.
    let dir = tempdir().unwrap();
    let f = dir.path().join("not-a-dir");
    std::fs::write(&f, b"x").unwrap();
    assert!(
        validate_credentials_dir(&f).is_err(),
        "a regular file at the credentials-dir path must fail closed (O_DIRECTORY)"
    );
    assert!(
        validate_credentials_dir(&dir.path().join("absent")).is_err(),
        "an absent credentials dir must fail closed"
    );
}
