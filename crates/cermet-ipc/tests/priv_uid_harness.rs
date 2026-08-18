//! The PRIVILEGED second-uid harness.
//!
//! The entire cermetd security claim is a kernel boundary: after the uid flip an
//! agent running under a *different* uid must (1) be attributed to its OWN uid by
//! the daemon's `peer_cred` path, and (2) get a real `EACCES` reading the daemon's
//! `0600` key/DB files. A peercred shim bug is an auth bypass, so this proof must be
//! REAL — a fork that actually `setuid`s to a second uid, not a stub.
//!
//! These tests do real privileged syscalls (`fork`, `setuid`, `chown`), so they are
//! gated: they only RUN as root with `CERMET_PRIV_TEST=1`. Without privilege they
//! SKIP LOUDLY (print the reason and return green) — a silent pass would let a broken
//! boundary ship. Run via `scripts/priv-test.sh` (CI calls it with `sudo`).
//!
//! Linux: `peer_cred` -> `SO_PEERCRED`. macOS: `xucred` + `getpeereid`. Both attribute
//! the accepted fd to the CONNECTING peer's uid; this harness proves that across a real
//! uid gap.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use cermet_ipc::peer::peer_cred;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chown, fork, getuid, setgid, setuid, ForkResult, Gid, Uid};

/// Bound on every blocking accept/connect in this harness. Without it a child whose
/// `connect()` is denied at an ANCESTOR directory would never reach the socket, and the
/// parent's `accept()` would hang the test forever.
/// A timeout converts that hang into a LOUD failure instead.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Make `dir` traversable (searchable) by ANY uid — `0o711` — so a process
/// under a dropped uid can `connect()`/`open()` a leaf inside it. The leaf itself stays
/// `0o600`, so the ONLY thing that can deny the dropped uid is the leaf's own permission
/// model, not an inaccessible ancestor. `tempfile::tempdir()` defaults to `0o700` (owner
/// only), which would deny at ancestor traversal and prove the WRONG thing.
///
/// `0o711` grants `--x` (search) to group+other but NOT `r` (list) or `w` — a dropped uid
/// can resolve a known path through the dir but cannot enumerate or write it. That is the
/// minimum needed to make the leaf's 0600 the sole gate.
fn make_traversable(dir: &Path) {
    let perms = std::fs::Permissions::from_mode(0o711);
    std::fs::set_permissions(dir, perms).expect("chmod parent dir to 0o711 (traversable)");
}

/// Force a bound UNIX-domain socket LEAF to an exact mode and assert it stuck.
///
/// `UnixListener::bind` creates the socket inode with `0o777 & !umask`, so the leaf's mode is
/// environment-dependent (the caller's umask). On Linux, pathname-UDS permissions can gate
/// `connect()` — so without pinning the leaf, a cross-uid `connect()` could be denied (or
/// allowed) by the SOCKET's own ACL rather than reaching the peercred path. That would turn a
/// peercred-attribution proof into an env-dependent ACL test. We chmod the leaf to a known,
/// connect-permitting mode (`0o666`) and assert the on-disk mode matches, BEFORE any fork, so
/// the only thing exercised by the cross-uid connect is the kernel's peercred attribution.
fn chmod_socket_leaf(sock: &Path, mode: u32) {
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(mode))
        .unwrap_or_else(|e| panic!("chmod socket leaf {} to {:#o}: {e}", sock.display(), mode));
    let got = std::fs::metadata(sock)
        .unwrap_or_else(|e| panic!("stat socket leaf {}: {e}", sock.display()))
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        got,
        mode,
        "socket leaf {} mode must be {:#o} after chmod (got {:#o}); a bind()+umask leaf could \
         gate connect() and make the peercred proof an env-dependent ACL test",
        sock.display(),
        mode,
        got,
    );
}

/// Bounded `accept()`: poll a non-blocking listener until a peer connects or `IO_TIMEOUT`
/// elapses. If the connecting child is denied at an ancestor (the old hang), the
/// peer never arrives — this converts that into a LOUD timeout panic instead of a forever
/// hang. Returns the accepted stream (set back to blocking for the subsequent read).
fn accept_within_timeout(listener: &UnixListener) -> UnixStream {
    listener
        .set_nonblocking(true)
        .expect("set listener non-blocking");
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _addr)) => {
                stream
                    .set_nonblocking(false)
                    .expect("set accepted stream blocking");
                return stream;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "accept() timed out after {IO_TIMEOUT:?} with no peer — the connecting \
                     child was likely denied at an ANCESTOR dir before reaching the socket \
                    , or the fork/connect failed"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("accept() failed: {e}"),
        }
    }
}

/// Ancestor guard: assert every ANCESTOR of `leaf` up to and including `root` is traversable
/// by "other" (the `o+x` bit, `0o001`). If any ancestor lacks it, a denial reading/connecting
/// to `leaf` from a dropped uid could come from ancestor traversal rather than the leaf's own
/// 0600 mode — i.e. the proof would prove the wrong thing. Panics (LOUD) on the first
/// non-traversable ancestor so a mis-set parent can never silently weaken the proof.
fn assert_ancestors_traversable(leaf: &Path, root: &Path) {
    let mut cur = leaf.parent();
    while let Some(dir) = cur {
        let mode = std::fs::metadata(dir)
            .unwrap_or_else(|e| panic!("stat ancestor {}: {e}", dir.display()))
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o001,
            0o001,
            "ancestor {} (mode {:#o}) is NOT traversable by other (o+x); an EACCES from a \
             dropped uid would come from this ancestor, not the leaf's 0600 — the proof would \
             prove the WRONG thing",
            dir.display(),
            mode & 0o7777,
        );
        if dir == root {
            break;
        }
        cur = dir.parent();
    }
}

/// Decide whether the privileged path may run, or print a LOUD skip and bail.
///
/// Returns `Some(other_uid)` when privileged: a distinct, non-root uid to drop to.
/// Returns `None` after printing `SKIPPED: ...` to stderr — the caller then returns
/// green. We NEVER silently pass: every skip names the missing precondition.
fn require_privilege(test_name: &str) -> Option<u32> {
    let want = std::env::var("CERMET_PRIV_TEST").ok().as_deref() == Some("1");
    let is_root = getuid().is_root();

    if !want {
        eprintln!(
            "SKIPPED: needs root/CERMET_PRIV_TEST  ({test_name}: set CERMET_PRIV_TEST=1 and run as root via scripts/priv-test.sh)"
        );
        return None;
    }
    if !is_root {
        // The operator asked for the privileged path but we are not root: this is a
        // HARD skip, not a pass — we cannot setuid to a second uid without privilege.
        eprintln!(
            "SKIPPED: needs root/CERMET_PRIV_TEST  ({test_name}: CERMET_PRIV_TEST=1 set but euid={} is not root)",
            getuid().as_raw()
        );
        return None;
    }

    let other = pick_other_uid();
    if other == getuid().as_raw() {
        eprintln!(
            "SKIPPED: needs root/CERMET_PRIV_TEST  ({test_name}: could not resolve a SECOND uid distinct from our own; set CERMET_TEST_OTHER_UID)"
        );
        return None;
    }
    Some(other)
}

/// The second uid to drop the child to. Prefer an explicit `CERMET_TEST_OTHER_UID`;
/// otherwise fall back to `nobody` (65534), the conventional unprivileged uid present
/// on Linux and macOS. Never returns root's uid intentionally; callers re-check.
fn pick_other_uid() -> u32 {
    if let Some(v) = std::env::var("CERMET_TEST_OTHER_UID")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
    {
        return v;
    }
    65534 // nobody
}

/// Parse a gid from env `var`, falling back to `default`. The defaults are high synthetic gids the
/// root parent is NOT a member of, so a cross-uid connect is gated by the group membership we set
/// explicitly, never by an owner match or an inherited supplementary group. Mirrors the inline
/// parsing the older group-socket proofs use, shared by the new opposite-plane deny proofs.
fn env_gid(var: &str, default: u32) -> u32 {
    std::env::var(var)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Fully drop privileges to `uid` in the forked child: groups first, then gid, then
/// uid (order matters — once uid drops you can't change groups). A failure here must
/// abort the child with a nonzero code so the parent's assertion fails LOUD, never
/// continue as root (which would make the cross-uid claim a lie).
fn drop_to(uid: u32) {
    let u = Uid::from_raw(uid);
    let g = Gid::from_raw(uid);
    // `setgroups` is Linux-only in nix 0.26 (gated out on macOS). On Linux, drop the
    // supplementary groups too so the child has NO leftover privileged group membership.
    #[cfg(target_os = "linux")]
    if let Err(e) = nix::unistd::setgroups(&[g]) {
        eprintln!("child: setgroups failed: {e}");
        std::process::exit(91);
    }
    if let Err(e) = setgid(g) {
        eprintln!("child: setgid failed: {e}");
        std::process::exit(92);
    }
    if let Err(e) = setuid(u) {
        eprintln!("child: setuid failed: {e}");
        std::process::exit(93);
    }
    // Paranoia: confirm we are no longer root and cannot regain it.
    if getuid().as_raw() != uid || setuid(Uid::from_raw(0)).is_ok() {
        eprintln!("child: privilege drop did not stick");
        std::process::exit(94);
    }
}

/// (a) Cross-uid peercred: a child under a SECOND uid connects to our UDS; the parent
/// (still root) reads `peer_cred` off the accepted fd and asserts it is the CHILD's uid,
/// not the listener's. This is the auth-bypass guard for the peercred shim.
#[test]
fn cross_uid_peercred_reads_connecting_uid() {
    let Some(other_uid) = require_privilege("cross_uid_peercred_reads_connecting_uid") else {
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("xuid.sock");
    let listener = UnixListener::bind(&path).expect("bind");

    // Make the socket's parent dir TRAVERSABLE by the dropped uid (0711) so the
    // child's connect() reaches the SOCKET, not an EACCES at an inaccessible ancestor — and
    // assert no ancestor can deny, so what this test proves is the peercred path, not a
    // directory-traversal artifact.
    make_traversable(dir.path());
    assert_ancestors_traversable(&path, dir.path());

    // Pin the socket LEAF's own mode (and assert it) so the cross-uid connect() is
    // gated ONLY by the kernel peercred path, never by the leaf's bind()+umask ACL. 0666 lets
    // any uid connect; the parent dir at 0711 already prevents enumeration. Do this BEFORE the
    // fork so the child's connect sees a deterministic, connect-permitting socket inode.
    chmod_socket_leaf(&path, 0o666);

    // SAFETY: single-threaded test binary at fork time; the child only does
    // simple syscalls + a blocking connect, then exits without returning to test code.
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            drop_to(other_uid);
            // Connect from the second uid. A small write makes the connection real.
            match UnixStream::connect(&path) {
                Ok(mut s) => {
                    // Bound the read so a parent that never replies cannot hang the child.
                    let _ = s.set_read_timeout(Some(IO_TIMEOUT));
                    let _ = s.write_all(b"x");
                    // Hold the connection open until the parent has read peercred.
                    let mut buf = [0u8; 1];
                    let _ = s.read(&mut buf);
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!("child: connect failed: {e}");
                    std::process::exit(95);
                }
            }
        }
        ForkResult::Parent { child } => {
            let server_conn = accept_within_timeout(&listener);
            let cred = peer_cred(server_conn.as_raw_fd()).expect("peer_cred on accepted fd");
            assert_eq!(
                cred.uid,
                other_uid,
                "accepted-fd peer uid must be the CONNECTING child's uid ({other_uid}), \
                 not the listener's ({}). A mismatch here is an AUTH BYPASS.",
                getuid().as_raw()
            );
            assert_ne!(
                cred.uid,
                getuid().as_raw(),
                "the proof is only meaningful across DISTINCT uids"
            );
            // Release the child, then reap it.
            drop(server_conn);
            let status = waitpid(child, None).expect("waitpid");
            assert_eq!(
                status,
                WaitStatus::Exited(child, 0),
                "second-uid child must exit cleanly; nonzero => privilege-drop/connect failure"
            );
        }
    }
}

/// (b) EACCES: a `0600` file owned by uid X must be UNREADABLE by a process under a
/// different uid. This is the post-flip claim for the master key / DBs distilled to one
/// file. The child drops to a second uid and must get `EACCES` (or `EPERM`) reading it.
#[test]
fn agent_uid_gets_eacces_on_0600_file_owned_by_other_uid() {
    let Some(agent_uid) =
        require_privilege("agent_uid_gets_eacces_on_0600_file_owned_by_other_uid")
    else {
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    // Model the daemon's key file: owned by the SERVICE uid (root here stands in), 0600.
    let key_path = dir.path().join("master.key");
    write_0600(&key_path, b"PRETEND-MASTER-KEY");
    let service_uid = getuid().as_raw();
    assert_ne!(
        service_uid, agent_uid,
        "service uid and agent uid must differ for the EACCES claim to mean anything"
    );

    // The crux: make the parent dir TRAVERSABLE by the agent uid (0711) and assert
    // no ancestor can deny. The default 0700 tempdir would deny at ANCESTOR traversal, so a
    // resulting EACCES would prove the directory mode, NOT the 0600 key file. With a
    // traversable parent, the child's denial reading the leaf can ONLY be the leaf's 0600 —
    // which is the post-flip claim we actually need to prove.
    make_traversable(dir.path());
    assert_ancestors_traversable(&key_path, dir.path());

    // Sanity: the owner CAN read it (the daemon itself must still work).
    let owner_read =
        std::fs::read(&key_path).expect("owner (root) must be able to read its 0600 key");
    assert_eq!(owner_read, b"PRETEND-MASTER-KEY");

    let key_path_for_child = key_path.clone();
    let dir_for_child = dir.path().to_path_buf();
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            drop_to(agent_uid);
            // First PROVE the denial is NOT an ancestor artifact — the dropped uid
            // must be able to traverse the parent (stat the leaf path through it). If the
            // parent denied traversal, exit 44 so the parent panics "ancestor, not file".
            // `metadata` resolves the full path: success means traversal worked and the
            // file exists; the read below then tests the FILE's own 0600.
            match std::fs::metadata(&key_path_for_child) {
                Ok(_) => { /* traversed parent + statted leaf — ancestor is NOT the gate */ }
                Err(e) => {
                    eprintln!(
                        "child: could not stat the key path as agent uid ({e}); parent dir is \
                         NOT traversable — this would be an ANCESTOR denial, not a 0600 proof"
                    );
                    std::process::exit(44);
                }
            }
            match std::fs::read(&key_path_for_child) {
                Ok(_) => {
                    // CATASTROPHE: a different uid read the 0600 key. Boundary is broken.
                    eprintln!("child: READ the 0600 key as a different uid — boundary breached!");
                    std::process::exit(42);
                }
                Err(e) => {
                    let raw = e.raw_os_error().unwrap_or(0);
                    // The denial must be EACCES (13). With a traversable parent, an EACCES on
                    // the leaf read can ONLY be the file's 0600 mode — the claim we want. We
                    // require EACCES specifically (not EPERM/ENOENT) so a different failure
                    // mode cannot masquerade as the boundary holding.
                    if raw == nix::libc::EACCES {
                        std::process::exit(0);
                    }
                    eprintln!(
                        "child: key read failed but NOT with EACCES (raw={raw}, {e}); expected \
                         the 0600 file's own permission denial"
                    );
                    std::process::exit(43);
                }
            }
        }
        ForkResult::Parent { child } => {
            // Owner can still traverse + read (the daemon must keep working post-flip).
            assert!(
                std::fs::metadata(&dir_for_child).is_ok(),
                "owner must still see the traversable parent dir"
            );
            let status = waitpid(child, None).expect("waitpid");
            match status {
                WaitStatus::Exited(_, 0) => { /* child got EACCES on the FILE — boundary holds */ }
                WaitStatus::Exited(_, 42) => panic!(
                    "AUTH BYPASS: a process under uid {agent_uid} READ a 0600 file owned by uid {service_uid}"
                ),
                WaitStatus::Exited(_, 44) => panic!(
                    "INVALID PROOF: the agent uid was denied at an ANCESTOR dir, not the 0600 \
                     file — the parent was not traversable. Fix make_traversable."
                ),
                WaitStatus::Exited(_, 43) => panic!(
                    "the leaf read failed with a NON-EACCES error; the 0600 file-permission \
                     proof is inconclusive (see child stderr)"
                ),
                other => panic!(
                    "second-uid child failed the EACCES probe (status {other:?}); expected a clean EACCES on the 0600 file"
                ),
            }
        }
    }
}

/// Write `bytes` to `path` with mode 0600 (owner-only), matching the daemon's key/DB perms.
fn write_0600(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .expect("create 0600 key file");
    f.write_all(bytes).expect("write key bytes");
    // chown to self is a no-op but makes the ownership model legible and survives umask.
    chown(path, Some(getuid()), None).expect("chown key file to service uid");
}

/// Pairwise matrix — the agent uid gets a real EACCES reading the daemon's `0600 vault.db`.
///
/// `vault.db` is the durable broker/vault plaintext store — the exact durable secret material the
/// core-invariant says NEVER leaves the trusted daemon uid. It is `0600` owned by the daemon (service)
/// uid; root stands in here. A process under the agent uid must be denied the read at the kernel, so
/// the raw credential cannot be exfiltrated by a compromised agent simply reading the daemon's DB file.
/// The `state` leg of the state/pin/key triad (master.key + sentence.pin are proven by their own
/// tests). Ancestor discipline keeps the EACCES the DB's own 0600, not an ancestor artifact.
#[test]
fn agent_uid_gets_eacces_on_vault_db() {
    let Some(agent_uid) = require_privilege("agent_uid_gets_eacces_on_vault_db") else {
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    // Model the daemon's vault DB: 0600, owned by the SERVICE uid (root stands in here).
    let db_path = dir.path().join("vault.db");
    write_0600(&db_path, b"PRETEND-SQLITE-VAULT-WITH-CIPHERTEXT");
    let daemon_uid = getuid().as_raw();
    assert_ne!(
        daemon_uid, agent_uid,
        "the daemon (vault owner) and the agent uid must differ for the EACCES claim to mean anything"
    );

    make_traversable(dir.path());
    assert_ancestors_traversable(&db_path, dir.path());

    let owner_read =
        std::fs::read(&db_path).expect("the daemon (owner) must read its own 0600 vault.db");
    assert_eq!(owner_read, b"PRETEND-SQLITE-VAULT-WITH-CIPHERTEXT");

    let db_for_child = db_path.clone();
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            drop_to(agent_uid);
            match std::fs::metadata(&db_for_child) {
                Ok(_) => { /* traversed parent + statted leaf — ancestor is NOT the gate */ }
                Err(e) => {
                    eprintln!("child: could not stat vault.db as agent uid ({e}); ancestor denial");
                    std::process::exit(44);
                }
            }
            match std::fs::read(&db_for_child) {
                Ok(_) => {
                    eprintln!(
                        "child: READ the daemon's 0600 vault.db as the agent uid — durable \
                               credential plaintext exfiltrable; boundary breached!"
                    );
                    std::process::exit(42);
                }
                Err(e) => {
                    let raw = e.raw_os_error().unwrap_or(0);
                    if raw == nix::libc::EACCES {
                        std::process::exit(0);
                    }
                    eprintln!("child: vault.db read failed but NOT with EACCES (raw={raw}, {e})");
                    std::process::exit(43);
                }
            }
        }
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).expect("waitpid");
            match status {
                WaitStatus::Exited(_, 0) => { /* agent uid got EACCES on the vault DB — boundary holds */ }
                WaitStatus::Exited(_, 42) => panic!(
                    "AUTH BYPASS: a process under the agent uid {agent_uid} READ the daemon's 0600 \
                     vault.db (owned by uid {daemon_uid}) — durable credential plaintext exfiltrable"
                ),
                WaitStatus::Exited(_, 44) => panic!(
                    "INVALID PROOF: the agent uid was denied at an ANCESTOR dir, not the vault.db's \
                     0600. Fix make_traversable."
                ),
                WaitStatus::Exited(_, 43) => panic!(
                    "the vault.db read failed with a NON-EACCES error; the 0600 proof is inconclusive"
                ),
                other => panic!("second-uid child failed the vault.db EACCES probe (status {other:?})"),
            }
        }
    }
}

/// (c) Ancestor-discipline regression — NON-privileged, runs on every host (incl. CI dev boxes).
///
/// The privileged probes (a)/(b) only mean something if the dropped uid's denial comes from
/// the LEAF's 0600, not an inaccessible ancestor. This pins the two helpers that guarantee
/// it. We do NOT assume the platform default for a fresh tempdir (it is 0700 on Linux but
/// 0755 on macOS, which is exactly why the fix must FORCE the mode rather than rely on the
/// default): we first STARVE the parent (0700, owner-only — the worst case that would prove
/// the wrong thing), confirm the ancestor guard then REJECTS it, then `make_traversable` and
/// confirm the guard accepts a 0711 dir while the leaf stays 0600.
#[test]
fn parent_forced_traversable_but_not_readable_and_leaf_stays_0600() {
    let dir = tempfile::tempdir().expect("tempdir");
    let key_path = dir.path().join("master.key");
    write_0600(&key_path, b"PRETEND-MASTER-KEY");

    // Worst case: parent owner-only 0700. A dropped uid would be denied at THIS ancestor,
    // not at the leaf — so the ancestor guard must reject it (the proof would be a lie).
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let starved = std::panic::catch_unwind(|| assert_ancestors_traversable(&key_path, dir.path()));
    assert!(
        starved.is_err(),
        "a 0700 parent must be REJECTED by the ancestor guard — otherwise an ancestor denial \
         masquerades as a leaf-permission proof"
    );

    // The fix: force the parent traversable. Exactly 0711 — search for other, NOT read/write.
    make_traversable(dir.path());
    let after = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o7777;
    assert_eq!(
        after, 0o711,
        "make_traversable must yield exactly 0711, got {after:#o}"
    );
    assert_eq!(
        after & 0o004,
        0,
        "other must NOT have read (cannot enumerate the dir)"
    );
    assert_eq!(after & 0o002, 0, "other must NOT have write");

    // Leaf must stay owner-only 0600 — it is the SOLE gate now.
    let leaf = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o7777;
    assert_eq!(leaf, 0o600, "leaf key file must be 0600, got {leaf:#o}");

    // With the parent at 0711 the ancestor guard must now PASS.
    assert_ancestors_traversable(&key_path, dir.path());
}

// The per-agent-uid boundary across a real uid gap: (c) the agent uid gets EACCES on
// the human's 0600 console.token, and (a) the agent.sock 0660 cermet-agents group ACL admits a member
// (attributed to its uid) but denies a non-member. The ctl uid-gate half of (b) is a daemon-logic
// check, proven without privilege in cermet-daemon.

/// Drop to `uid` with an explicit primary `gid` (unlike [`drop_to`], which ties gid to uid) — the
/// group-socket proof needs membership decoupled from uid. On Linux also clear inherited supplementary
/// groups; on macOS (no `setgroups` in nix 0.26) the chosen gids are high synthetic ids root isn't in.
fn drop_to_uid_gid(uid: u32, gid: u32) {
    let u = Uid::from_raw(uid);
    let g = Gid::from_raw(gid);
    #[cfg(target_os = "linux")]
    if let Err(e) = nix::unistd::setgroups(&[g]) {
        eprintln!("child: setgroups failed: {e}");
        std::process::exit(91);
    }
    if let Err(e) = setgid(g) {
        eprintln!("child: setgid failed: {e}");
        std::process::exit(92);
    }
    if let Err(e) = setuid(u) {
        eprintln!("child: setuid failed: {e}");
        std::process::exit(93);
    }
    if getuid().as_raw() != uid || setuid(Uid::from_raw(0)).is_ok() {
        eprintln!("child: privilege drop did not stick");
        std::process::exit(94);
    }
}

/// Pin a bound socket leaf to an exact owning group + mode (asserting both stuck) — the 0660-group
/// ACL is what gates the cross-uid connect, so it must be deterministic, not a bind()+umask accident.
/// Models `agent.sock`, where the group is inherited from the setgid `cermet-agents` dir.
fn chgrp_chmod_socket_leaf(sock: &Path, gid: u32, mode: u32) {
    chown(sock, None, Some(Gid::from_raw(gid)))
        .unwrap_or_else(|e| panic!("chgrp socket leaf {} to gid {gid}: {e}", sock.display()));
    chmod_socket_leaf(sock, mode);
    let got_gid = std::fs::metadata(sock)
        .unwrap_or_else(|e| panic!("stat socket leaf {}: {e}", sock.display()))
        .gid();
    assert_eq!(
        got_gid, gid,
        "socket leaf {} must be group {gid} after chgrp (got {got_gid}); the 0660 group ACL is the \
         agent.sock cross-uid boundary and must be pinned, not left to inheritance accident",
        sock.display(),
    );
}

/// Cross-uid connect-DENIED probe — the shared engine of the two opposite-plane FS-ACL proofs.
///
/// Fork a child, drop it to `(uid, gid)`, and attempt `connect(sock)`. A correctly-gated 0660 group
/// socket refuses a non-owner/non-member connect() with EACCES BEFORE the connection ever queues, so
/// the parent does NOT accept — the refusal is the whole proof. `plane` names the boundary for LOUD
/// panics. A successful connect, or a denial with any errno OTHER than EACCES, is a loud panic, never
/// a silent pass: a stranger reaching the OPPOSITE authority plane across the uid gap is a breach.
fn assert_cross_uid_connect_denied(sock: &Path, uid: u32, gid: u32, plane: &str) {
    // SAFETY: single-threaded test binary at fork time; the child only does a privilege drop and a
    // blocking connect, then exits without returning to test code.
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            drop_to_uid_gid(uid, gid);
            match UnixStream::connect(sock) {
                Ok(_) => {
                    eprintln!(
                        "child: CONNECTED to {plane} as uid {uid} (gid {gid}) — the 0660 group ACL \
                         did NOT gate connect(); the two authority planes are NOT separated here"
                    );
                    std::process::exit(42);
                }
                Err(e) => {
                    let raw = e.raw_os_error().unwrap_or(0);
                    if raw == nix::libc::EACCES {
                        std::process::exit(0);
                    }
                    eprintln!(
                        "child: connect to {plane} denied but NOT with EACCES (raw={raw}, {e}); \
                         expected the 0660 group ACL's own denial"
                    );
                    std::process::exit(43);
                }
            }
        }
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).expect("waitpid");
            match status {
                WaitStatus::Exited(_, 0) => { /* stranger denied with EACCES — plane separation holds */ }
                WaitStatus::Exited(_, 42) => panic!(
                    "BOUNDARY BREACH: a stranger uid {uid} reached {plane} across the uid gap. Either \
                     the socket ACL is wrong, or this host does not gate UNIX-socket connect() by mode \
                     (then plane separation rests on the daemon peercred gate alone — re-verify the \
                     install on THIS host before relying on the FS layer)"
                ),
                WaitStatus::Exited(_, 43) => panic!(
                    "the {plane} connect was denied with a NON-EACCES error; the 0660 group ACL proof \
                     is inconclusive (see child stderr)"
                ),
                other => {
                    panic!("stranger-uid child failed the {plane} deny probe (status {other:?})")
                }
            }
        }
    }
}

/// (c) The console token gates the human-only ctl plane; if the agent could read it (`cat
/// ~/.cermet/console.token`) it could forge an approval. It's 0600 human-owned, the agent is a
/// different uid, so the kernel denies the read. Ancestor discipline keeps the EACCES the
/// token's own 0600, not an ancestor artifact.
#[test]
fn agent_uid_gets_eacces_on_console_token() {
    let Some(agent_uid) = require_privilege("agent_uid_gets_eacces_on_console_token") else {
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    // Model the human's console token: owned by the APPROVER uid (root stands in here), 0600.
    let token_path = dir.path().join("console.token");
    write_0600(&token_path, b"console-token-PRETEND-SECRET");
    let approver_uid = getuid().as_raw();
    assert_ne!(
        approver_uid, agent_uid,
        "the approver (token owner) and the agent uid must differ for the EACCES claim to mean \
         anything — the whole point is the agent is NOT the human"
    );

    // Traversable parent + assert no ancestor can deny, so the child's denial is the token's
    // own 0600, not a directory-mode artifact.
    make_traversable(dir.path());
    assert_ancestors_traversable(&token_path, dir.path());

    // Sanity: the human (owner) CAN read their own token — we only deny the foreign agent uid.
    let owner_read = std::fs::read(&token_path)
        .expect("the approver (owner) must read its own 0600 console token");
    assert_eq!(owner_read, b"console-token-PRETEND-SECRET");

    let token_for_child = token_path.clone();
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            drop_to(agent_uid);
            // First prove the parent is traversable (else an EACCES would be an ancestor artifact).
            match std::fs::metadata(&token_for_child) {
                Ok(_) => { /* traversed parent + statted leaf — ancestor is NOT the gate */ }
                Err(e) => {
                    eprintln!(
                        "child: could not stat console.token as agent uid ({e}); parent not \
                         traversable — would be an ANCESTOR denial, not a 0600 proof"
                    );
                    std::process::exit(44);
                }
            }
            match std::fs::read(&token_for_child) {
                Ok(_) => {
                    eprintln!(
                        "child: READ the human's 0600 console.token as the agent uid — the \
                               agent could forge an approval; boundary breached!"
                    );
                    std::process::exit(42);
                }
                Err(e) => {
                    let raw = e.raw_os_error().unwrap_or(0);
                    if raw == nix::libc::EACCES {
                        std::process::exit(0);
                    }
                    eprintln!(
                        "child: console.token read failed but NOT with EACCES (raw={raw}, {e})"
                    );
                    std::process::exit(43);
                }
            }
        }
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).expect("waitpid");
            match status {
                WaitStatus::Exited(_, 0) => { /* agent uid got EACCES on the token — boundary holds */
                }
                WaitStatus::Exited(_, 42) => panic!(
                    "AUTH BYPASS: a process under the agent uid {agent_uid} READ the human's 0600 \
                     console.token (owned by uid {approver_uid}) — it could forge a ctl approval"
                ),
                WaitStatus::Exited(_, 44) => panic!(
                    "INVALID PROOF: the agent uid was denied at an ANCESTOR dir, not the token's \
                     0600. Fix make_traversable."
                ),
                WaitStatus::Exited(_, 43) => panic!(
                    "the console.token read failed with a NON-EACCES error; the 0600 proof is \
                     inconclusive (see child stderr)"
                ),
                other => panic!(
                    "second-uid child failed the console.token EACCES probe (status {other:?})"
                ),
            }
        }
    }
}

/// (a) The `agent.sock` ACL across a real uid gap. The daemon binds `agent.sock` `0660`
/// owned by the `cermet-agents` group; an agent uid reaches it ONLY by group membership, and the
/// daemon attributes the connection to that uid via peercred. A uid NOT in `cermet-agents` (e.g. an
/// approver in the DISJOINT `cermet-approvers` group, or any other account) gets EACCES — that group
/// boundary is what the agent/approver separation turns on. We prove BOTH halves on the same bound
/// 0660 group socket: a member connects (and is attributed to its own uid); a non-member is denied.
#[test]
fn cermet_agents_member_connects_0660_socket_nonmember_denied() {
    let Some(member_uid) =
        require_privilege("cermet_agents_member_connects_0660_socket_nonmember_denied")
    else {
        return;
    };

    // High synthetic ids the root parent is NOT a member of (so no inherited supplementary group can
    // alias the agents gid and let a "non-member" match). Overridable for hosts where these collide.
    let agents_gid: u32 = std::env::var("CERMET_TEST_AGENTS_GID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65533);
    let nonmember_uid: u32 = std::env::var("CERMET_TEST_NONMEMBER_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65532);
    let nonmember_gid: u32 = std::env::var("CERMET_TEST_NONMEMBER_GID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65531);

    let owner_uid = getuid().as_raw();
    // The proof only means something if member, non-member, the socket owner, and the two gids are all
    // genuinely distinct and non-root — otherwise an "allow" could be owner-match, not group-match.
    for (label, id) in [("member_uid", member_uid), ("nonmember_uid", nonmember_uid)] {
        assert_ne!(id, 0, "{label} must not be root");
        assert_ne!(
            id, owner_uid,
            "{label} must differ from the socket owner uid so a connect is gated by GROUP, not owner"
        );
    }
    assert_ne!(
        member_uid, nonmember_uid,
        "member and non-member uids must differ"
    );
    assert_ne!(
        agents_gid, nonmember_gid,
        "the agents gid and the non-member gid must differ — that IS the membership boundary"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&path).expect("bind agent.sock");
    make_traversable(dir.path());
    assert_ancestors_traversable(&path, dir.path());
    // Pin the exact ACL: 0660 owned by the cermet-agents group.
    chgrp_chmod_socket_leaf(&path, agents_gid, 0o660);

    // --- (1) MEMBER: primary gid == agents_gid -> connect SUCCEEDS, attributed to the member uid. ---
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            drop_to_uid_gid(member_uid, agents_gid);
            match UnixStream::connect(&path) {
                Ok(mut s) => {
                    let _ = s.set_read_timeout(Some(IO_TIMEOUT));
                    let _ = s.write_all(b"x");
                    let mut buf = [0u8; 1];
                    let _ = s.read(&mut buf);
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!(
                        "child(member): connect to the 0660 cermet-agents socket FAILED ({e}); a \
                         group member must be able to reach agent.sock"
                    );
                    std::process::exit(95);
                }
            }
        }
        ForkResult::Parent { child } => {
            let conn = accept_within_timeout(&listener);
            let cred = peer_cred(conn.as_raw_fd()).expect("peer_cred on accepted fd");
            assert_eq!(
                cred.uid, member_uid,
                "the agent.sock connection must be attributed to the connecting agent uid \
                 ({member_uid}), not the listener's ({owner_uid})"
            );
            drop(conn);
            let status = waitpid(child, None).expect("waitpid");
            assert_eq!(
                status,
                WaitStatus::Exited(child, 0),
                "the cermet-agents member must connect cleanly to the 0660 agent.sock"
            );
        }
    }

    // --- (2) NON-MEMBER: not owner, gid != agents_gid -> connect DENIED with EACCES. ---
    // The parent does NOT accept: a correctly-gated connect() is refused before it ever queues.
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            drop_to_uid_gid(nonmember_uid, nonmember_gid);
            match UnixStream::connect(&path) {
                Ok(_) => {
                    eprintln!(
                        "child(non-member): CONNECTED to the 0660 cermet-agents agent.sock as a \
                         non-member — the group ACL did NOT gate connect on this host; the agent/\
                         approver socket separation does NOT hold here"
                    );
                    std::process::exit(42);
                }
                Err(e) => {
                    let raw = e.raw_os_error().unwrap_or(0);
                    if raw == nix::libc::EACCES {
                        std::process::exit(0);
                    }
                    eprintln!(
                        "child(non-member): connect denied but NOT with EACCES (raw={raw}, {e}); \
                         expected the 0660 group ACL's own denial"
                    );
                    std::process::exit(43);
                }
            }
        }
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).expect("waitpid");
            match status {
                WaitStatus::Exited(_, 0) => { /* non-member denied with EACCES — boundary holds */ }
                WaitStatus::Exited(_, 42) => panic!(
                    "BOUNDARY BREACH: a non-member uid {nonmember_uid} reached the 0660 \
                     cermet-agents agent.sock owned by uid {owner_uid}. Either the socket ACL is \
                     wrong, or this host does not gate UNIX-socket connect() by mode (then the \
                     agent.sock boundary rests on the directory ACL + uid gate, NOT the socket mode \
                     — re-verify the install on THIS host before relying on the demo beat)"
                ),
                WaitStatus::Exited(_, 43) => panic!(
                    "the non-member connect was denied with a NON-EACCES error; the 0660 group ACL \
                     proof is inconclusive (see child stderr)"
                ),
                other => panic!(
                    "non-member child failed the agent.sock deny probe (status {other:?})"
                ),
            }
        }
    }
}

/// Pairwise matrix — AGENT uid DENIED on ctl.sock (the FS-ACL layer).
///
/// ctl.sock is bound `0660` owned by the `cermet-approvers` group in the `2711 cermet:cermet-approvers`
/// dir (`ctl.rs:50`). An agent process is a member of `cermet-agents` ONLY — never `cermet-approvers` —
/// so the kernel refuses its `connect()` to ctl.sock with EACCES. This is the FS defense-in-depth half
/// of the agent→ctl denial; the PRIMARY boundary is the daemon's `ctl_authorized` uid gate (`ctl.rs:69`,
/// proven without privilege by `ctl_authorized_denies_the_agent_uid_closing_self_dealing`). Together
/// they make "a compromised agent cannot speak the approval plane" a kernel property at BOTH layers,
/// closing the self-dealing path. Skip-loudly-green without root, like every proof here.
#[test]
fn agent_uid_denied_on_0660_ctl_sock_owned_by_approvers_group() {
    let Some(agent_uid) =
        require_privilege("agent_uid_denied_on_0660_ctl_sock_owned_by_approvers_group")
    else {
        return;
    };

    let agents_gid = env_gid("CERMET_TEST_AGENTS_GID", 65533);
    let approvers_gid = env_gid("CERMET_TEST_APPROVERS_GID", 65530);
    let owner_uid = getuid().as_raw();
    assert_ne!(agent_uid, 0, "the agent uid must not be root");
    assert_ne!(
        agent_uid, owner_uid,
        "the agent uid must differ from the socket owner so the connect is gated by GROUP, not owner"
    );
    assert_ne!(
        agents_gid, approvers_gid,
        "agents and approvers gids must differ — that disjointness IS the plane boundary"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("ctl.sock");
    // Keep the listener bound (named `_listener`, not `_`) for the whole test so the child's connect
    // is refused by the ACL, not by ENOENT — the parent never accepts.
    let _listener = UnixListener::bind(&path).expect("bind ctl.sock");
    make_traversable(dir.path());
    assert_ancestors_traversable(&path, dir.path());
    // Pin the exact ctl.sock ACL: 0660 owned by the cermet-approvers group.
    chgrp_chmod_socket_leaf(&path, approvers_gid, 0o660);

    // The agent uid is in cermet-agents (agents_gid) ONLY — a stranger on the approvals plane.
    assert_cross_uid_connect_denied(&path, agent_uid, agents_gid, "ctl.sock (approvals plane)");
}

/// Pairwise matrix — APPROVER uid DENIED on agent.sock (the FS-ACL layer). The gate retarget
/// made the approver a STRANGER on the agent plane.
///
/// agent.sock is bound `0660` owned by the `cermet-agents` group; the approver is a member of
/// `cermet-approvers` ONLY, so the kernel refuses its `connect()` to agent.sock with EACCES. This
/// closes the UNSANCTIONED path: an approver process cannot silently open the agent plane directly
/// under its OWN uid. It does NOT (and is not meant to) forbid the SANCTIONED downward flow — by design
/// an approver may LAUNCH the agent through the sudo rule, dropping to the `cermet-agent` uid,
/// and separately approve on ctl; that flow is deliberate and runs as the agent uid, not the approver's.
/// What this proof pins is narrower and exact: the approver uid ITSELF is a stranger on the agent plane
/// at the FS-ACL layer. Skip-loudly-green without root, like every proof in this harness.
#[test]
fn approver_uid_denied_on_0660_agent_sock_owned_by_agents_group() {
    let Some(approver_uid) =
        require_privilege("approver_uid_denied_on_0660_agent_sock_owned_by_agents_group")
    else {
        return;
    };

    let agents_gid = env_gid("CERMET_TEST_AGENTS_GID", 65533);
    let approvers_gid = env_gid("CERMET_TEST_APPROVERS_GID", 65530);
    let owner_uid = getuid().as_raw();
    assert_ne!(approver_uid, 0, "the approver uid must not be root");
    assert_ne!(
        approver_uid, owner_uid,
        "the approver uid must differ from the socket owner so the connect is gated by GROUP, not owner"
    );
    assert_ne!(
        agents_gid, approvers_gid,
        "agents and approvers gids must differ — that disjointness IS the plane boundary"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("agent.sock");
    let _listener = UnixListener::bind(&path).expect("bind agent.sock");
    make_traversable(dir.path());
    assert_ancestors_traversable(&path, dir.path());
    // Pin the exact agent.sock ACL: 0660 owned by the cermet-agents group.
    chgrp_chmod_socket_leaf(&path, agents_gid, 0o660);

    // The approver is in cermet-approvers (approvers_gid) ONLY — a stranger on the agent plane.
    assert_cross_uid_connect_denied(
        &path,
        approver_uid,
        approvers_gid,
        "agent.sock (agent plane)",
    );
}

/// The agent uid gets a real EACCES reading the daemon's `0600 sentence.pin`.
/// The pin is the exact-byte authority evidence the daemon holds; if the agent could read AND write
/// it, it could forge the pin that makes a rules file it authored authoritative. It is `0600`
/// daemon-owned (the SERVICE uid; root stands in here), so the kernel denies the foreign agent uid.
/// Ancestor discipline keeps the EACCES the pin's own 0600, not an ancestor artifact.
#[test]
fn agent_uid_gets_eacces_on_sentence_pin() {
    let Some(agent_uid) = require_privilege("agent_uid_gets_eacces_on_sentence_pin") else {
        return;
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let pin_path = dir.path().join("sentence.pin");
    // Model the daemon's pin: 32 raw bytes, 0600, owned by the daemon (service) uid.
    write_0600(&pin_path, &[0x5au8; 32]);
    let daemon_uid = getuid().as_raw();
    assert_ne!(
        daemon_uid, agent_uid,
        "the daemon (pin owner) and the agent uid must differ for the EACCES claim to mean anything"
    );

    make_traversable(dir.path());
    assert_ancestors_traversable(&pin_path, dir.path());

    let owner_read =
        std::fs::read(&pin_path).expect("the daemon (owner) must read its own 0600 pin");
    assert_eq!(owner_read.len(), 32);

    let pin_for_child = pin_path.clone();
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            drop_to(agent_uid);
            match std::fs::metadata(&pin_for_child) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "child: could not stat sentence.pin as agent uid ({e}); ancestor denial"
                    );
                    std::process::exit(44);
                }
            }
            match std::fs::read(&pin_for_child) {
                Ok(_) => {
                    eprintln!(
                        "child: READ the daemon's 0600 sentence.pin as the agent uid — the \
                               agent could forge authority; boundary breached!"
                    );
                    std::process::exit(42);
                }
                Err(e) => {
                    let raw = e.raw_os_error().unwrap_or(0);
                    if raw == nix::libc::EACCES {
                        std::process::exit(0);
                    }
                    eprintln!(
                        "child: sentence.pin read failed but NOT with EACCES (raw={raw}, {e})"
                    );
                    std::process::exit(43);
                }
            }
        }
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).expect("waitpid");
            match status {
                WaitStatus::Exited(_, 0) => {}
                WaitStatus::Exited(_, 42) => panic!(
                    "AUTH BYPASS: a process under the agent uid {agent_uid} READ the daemon's 0600 \
                     sentence.pin (owned by uid {daemon_uid}) — it could forge sentence authority"
                ),
                WaitStatus::Exited(_, 44) => panic!(
                    "INVALID PROOF: the agent uid was denied at an ANCESTOR dir, not the pin's 0600 \
                    . Fix make_traversable."
                ),
                WaitStatus::Exited(_, 43) => panic!(
                    "the sentence.pin read failed with a NON-EACCES error; the 0600 proof is inconclusive"
                ),
                other => panic!("second-uid child failed the sentence.pin EACCES probe (status {other:?})"),
            }
        }
    }
}

/// The daemon reads the approver-owned `0640` rules file via the `cermet`
/// GROUP, while a third uid in NEITHER role is denied. The rules file is `0640 <approver>:cermet` in
/// the setgid dir; the uid-cermet daemon is a group member (primary gid == cermet), so its GROUP `r`
/// bit lets it read even though it is not the owner. A process that is neither the owner nor a cermet
/// member gets EACCES — that is exactly the cross-uid custody topology the ceremony installs.
#[test]
fn daemon_group_member_reads_0640_rules_nonmember_denied() {
    let Some(daemon_uid) =
        require_privilege("daemon_group_member_reads_0640_rules_nonmember_denied")
    else {
        return;
    };

    // Synthetic ids the root parent is not a member of.
    let cermet_gid: u32 = std::env::var("CERMET_TEST_CERMET_GID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65529);
    let third_uid: u32 = std::env::var("CERMET_TEST_NONMEMBER_UID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65532);
    let third_gid: u32 = std::env::var("CERMET_TEST_NONMEMBER_GID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65531);
    let approver_uid = getuid().as_raw(); // root stands in as the rules-file OWNER (the approver).

    assert_ne!(
        daemon_uid, approver_uid,
        "daemon uid must differ from the approver (file owner)"
    );
    assert_ne!(
        third_gid, cermet_gid,
        "the third uid must NOT be in the cermet group"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let rules = dir.path().join("rules.cermet");
    // 0640 owned by approver(root):cermet_gid — the exact ceremony ACL.
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o640)
            .open(&rules)
            .expect("create 0640 rules file");
        f.write_all(b"allow stripe.refund where amount <= 5000\n")
            .expect("write rules");
    }
    chown(
        &rules,
        Some(Uid::from_raw(approver_uid)),
        Some(Gid::from_raw(cermet_gid)),
    )
    .expect("chown rules to approver:cermet");
    std::fs::set_permissions(&rules, std::fs::Permissions::from_mode(0o640)).expect("0640");
    make_traversable(dir.path());
    assert_ancestors_traversable(&rules, dir.path());

    // (1) DAEMON: primary gid == cermet_gid, uid == daemon_uid (not the owner) → reads via GROUP r.
    let rules_for_daemon = rules.clone();
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            drop_to_uid_gid(daemon_uid, cermet_gid);
            match std::fs::read(&rules_for_daemon) {
                Ok(bytes) if bytes.starts_with(b"allow ") => std::process::exit(0),
                Ok(_) => std::process::exit(45),
                Err(e) => {
                    eprintln!(
                        "child(daemon): could NOT read the 0640 approver-owned rules via the cermet \
                         group ({e}); the daemon must be able to read the sentence file it evaluates"
                    );
                    std::process::exit(95);
                }
            }
        }
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).expect("waitpid");
            assert_eq!(
                status,
                WaitStatus::Exited(child, 0),
                "the uid-cermet daemon (group member) must read the 0640 approver-owned rules file"
            );
        }
    }

    // (2) THIRD uid: not owner, gid not cermet → EACCES.
    let rules_for_third = rules.clone();
    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            drop_to_uid_gid(third_uid, third_gid);
            match std::fs::read(&rules_for_third) {
                Ok(_) => {
                    eprintln!(
                        "child(third): READ the 0640 rules despite being neither owner nor cermet"
                    );
                    std::process::exit(42);
                }
                Err(e) => {
                    let raw = e.raw_os_error().unwrap_or(0);
                    if raw == nix::libc::EACCES {
                        std::process::exit(0);
                    }
                    eprintln!("child(third): rules read denied but NOT EACCES (raw={raw}, {e})");
                    std::process::exit(43);
                }
            }
        }
        ForkResult::Parent { child } => {
            let status = waitpid(child, None).expect("waitpid");
            match status {
                WaitStatus::Exited(_, 0) => {}
                WaitStatus::Exited(_, 42) => panic!(
                    "BOUNDARY BREACH: a uid ({third_uid}) neither owning nor in the cermet group READ \
                     the 0640 rules file — the cross-uid custody ACL does not hold on this host"
                ),
                WaitStatus::Exited(_, 43) => panic!(
                    "the third-uid rules read failed with a NON-EACCES error; proof inconclusive"
                ),
                other => panic!("third-uid child failed the 0640 rules deny probe (status {other:?})"),
            }
        }
    }
}

/// Pairwise matrix — the 0660 FS ACL is PERMISSIVE by design; the peercred gate is THE boundary.
///
/// The 0660 `agent.sock` ACL admits ANY member of `cermet-agents` — defense-in-depth, NOT the auth
/// boundary (never call the file mode the boundary). Under the three-uid retarget the
/// agent-socket gate resolves to `Some(cfg.agent_uid)` (`main.rs:303`) — an EXACT-ONE-UID allowlist
/// (`connection.rs:295`), replacing the old single-`approver_uid` denylist. So a uid that is a member
/// of BOTH `cermet-agents` AND `cermet-approvers` (but is NOT the configured `agent_uid`) still passes
/// the permissive 0660 FS ACL — and is then REJECTED at the daemon's peercred pre-frame gate, because
/// an allowlist of one admits exactly one. The old residual (a single-uid DENYLIST that leaked
/// every approver-ROLE member) is CLOSED by the retarget, not merely characterized.
///
/// This is ALSO why the DAEMON uid's exclusion from both planes is peercred, NOT filesystem EACCES:
/// the daemon OWNS the sockets, so the FS layer can never deny it — its
/// exclusion is that the exact-one-uid peercred allowlist does not name the daemon uid, so any
/// daemon-uid peer is rejected pre-frame just like this both-groups uid.
///
/// This test PINS the permissive FS-ACL fact the peercred gate backstops: the 0660 ACL admits a uid
/// whose group set contains the approvers gid in addition to the agents gid, and the accepted fd is
/// attributed to that uid via peercred. The daemon-side exact-one-uid admission/rejection is daemon
/// logic, proven without privilege in cermet-daemon. Linux models "both groups" literally via
/// supplementary groups; macOS (no `setgroups` in nix 0.26) models membership by the agents PRIMARY
/// gid — the socket ACL only ever consults agents membership, so additional approvers membership is
/// irrelevant to the connect outcome on either OS. Skip-loudly-green without root, like every proof here.
#[test]
fn uid_in_both_cermet_agents_and_approvers_passes_0660_agent_sock_acl() {
    let Some(both_groups_uid) =
        require_privilege("uid_in_both_cermet_agents_and_approvers_passes_0660_agent_sock_acl")
    else {
        return;
    };

    // High synthetic gids root is not a member of, so the connect is gated by GROUP membership we set,
    // not by an inherited supplementary group or an owner match.
    let agents_gid: u32 = std::env::var("CERMET_TEST_AGENTS_GID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65533);
    let approvers_gid: u32 = std::env::var("CERMET_TEST_APPROVERS_GID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(65530);

    let owner_uid = getuid().as_raw();
    assert_ne!(both_groups_uid, 0, "the both-groups uid must not be root");
    assert_ne!(
        both_groups_uid, owner_uid,
        "the both-groups uid must differ from the socket owner so the connect is gated by GROUP, not owner"
    );
    assert_ne!(
        agents_gid, approvers_gid,
        "agents and approvers gids must differ — gid-disjointness alone is not the boundary"
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("agent.sock");
    let listener = UnixListener::bind(&path).expect("bind agent.sock");
    make_traversable(dir.path());
    assert_ancestors_traversable(&path, dir.path());
    // The exact ACL: 0660 owned by the cermet-agents group.
    chgrp_chmod_socket_leaf(&path, agents_gid, 0o660);

    match unsafe { fork() }.expect("fork") {
        ForkResult::Child => {
            // Model a uid in BOTH groups: primary gid = agents_gid (so it passes the 0660 agents ACL);
            // on Linux ALSO a supplementary member of approvers_gid (it is an approver-role
            // member too). On macOS setgroups is unavailable, so primary agents membership stands in.
            let agid = Gid::from_raw(agents_gid);
            #[cfg(target_os = "linux")]
            if let Err(e) = nix::unistd::setgroups(&[agid, Gid::from_raw(approvers_gid)]) {
                eprintln!("child: setgroups(agents,approvers) failed: {e}");
                std::process::exit(91);
            }
            if let Err(e) = setgid(agid) {
                eprintln!("child: setgid failed: {e}");
                std::process::exit(92);
            }
            if let Err(e) = setuid(Uid::from_raw(both_groups_uid)) {
                eprintln!("child: setuid failed: {e}");
                std::process::exit(93);
            }
            if getuid().as_raw() != both_groups_uid || setuid(Uid::from_raw(0)).is_ok() {
                eprintln!("child: privilege drop did not stick");
                std::process::exit(94);
            }
            match UnixStream::connect(&path) {
                Ok(mut s) => {
                    let _ = s.set_read_timeout(Some(IO_TIMEOUT));
                    let _ = s.write_all(b"x");
                    let mut buf = [0u8; 1];
                    let _ = s.read(&mut buf);
                    std::process::exit(0);
                }
                Err(e) => {
                    eprintln!(
                        "child(both-groups): connect to the 0660 cermet-agents socket FAILED ({e}); a \
                         uid in cermet-agents must reach agent.sock REGARDLESS of also being in \
                         cermet-approvers — that overlap is exactly the case under test"
                    );
                    std::process::exit(95);
                }
            }
        }
        ForkResult::Parent { child } => {
            let conn = accept_within_timeout(&listener);
            let cred = peer_cred(conn.as_raw_fd()).expect("peer_cred on accepted fd");
            assert_eq!(
                cred.uid, both_groups_uid,
                "the agent.sock connection from a uid in BOTH groups must be attributed to that uid \
                 ({both_groups_uid}); the permissive 0660 FS ACL admits it despite its approvers-group \
                 membership — the daemon's exact-one-uid peercred allowlist (Some(agent_uid)) is what \
                 then rejects any peer that is not the configured agent uid"
            );
            drop(conn);
            let status = waitpid(child, None).expect("waitpid");
            assert_eq!(
                status,
                WaitStatus::Exited(child, 0),
                "a uid in both cermet-agents and cermet-approvers must connect cleanly to the 0660 \
                 agent.sock — the FS ACL is permissive by design (gid-disjointness does NOT exclude \
                 it); the daemon peercred exact-one-uid gate is the boundary that does"
            );
        }
    }
}
