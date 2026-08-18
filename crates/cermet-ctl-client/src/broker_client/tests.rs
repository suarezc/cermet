use super::*;
use cermet_ipc::codec::{read_frame, write_response_frame};
use serde_json::json;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};
use std::thread;
use tempfile::tempdir;

/// The test's own real uid — the trusted daemon identity the stub sockets are bound under
/// (tests run same-uid, so the stub IS the keyholder). New constructions pass this as
/// `expected_daemon_uid` so the positive path stays green.
fn this_uid() -> u32 {
    nix::unistd::getuid().as_raw()
}

/// Spin a stub ctl server that, for `n` connect-per-call connections, reads one `CtlRequest`,
/// hands it to `responder`, and writes the returned envelope. Returns the socket path + handle.
/// The bound socket is chmod'd to `mode` so the stub mirrors a real daemon's inode permissions
/// (the real `ctl.sock` is bound EXACTLY 0o660 by `serve::bind_socket_in_group`); per-connection
/// keyholder verification inspects this mode, so the stub MUST set it to look authentic.
fn stub_with_mode<F>(
    responder: F,
    n: usize,
    mode: u32,
) -> (tempfile::TempDir, PathBuf, thread::JoinHandle<()>)
where
    F: Fn(&CtlRequest) -> Value + Send + 'static,
{
    let dir = tempdir().unwrap();
    // Mirror a real daemon runtime dir: 0o700, owned by getuid() (the keyholder in same-uid
    // tests). tempfile::tempdir() honors the umask (0o755 under umask 022), so harden it
    // explicitly to satisfy the runtime-dir contract on the positive path.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("ctl.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    let handle = thread::spawn(move || {
        for _ in 0..n {
            let (mut conn, _) = listener.accept().unwrap();
            let req: CtlRequest = read_frame(&mut conn).unwrap();
            let resp = responder(&req);
            write_response_frame(&mut conn, &resp).unwrap();
        }
    });
    (dir, path, handle)
}

/// As [`stub_with_mode`] but bound at the real daemon's exact 0o660 — the default for the
/// transport/decode tests, which must pass cleanly through keyholder verification.
fn stub<F>(responder: F, n: usize) -> (tempfile::TempDir, PathBuf, thread::JoinHandle<()>)
where
    F: Fn(&CtlRequest) -> Value + Send + 'static,
{
    stub_with_mode(responder, n, 0o660)
}

#[tokio::test]
async fn decodes_uniform_ok_view() {
    let (_d, path, srv) = stub(|_| json!({"kind":"ok","view":[{"session_id":"s1"}]}), 1);
    let client = CtlBrokerClient::new(path, this_uid());
    let r = client.history().await.expect("ok");
    assert!(
        r.contains("session_id"),
        "view payload is returned verbatim: {r}"
    );
    srv.join().unwrap();
}

#[tokio::test]
async fn prepare_and_authority_status_decode_as_typed_views() {
    let (_d, path, server) = stub(
        |request| match request {
            CtlRequest::PrepareSentences { candidate_text } => {
                assert_eq!(candidate_text, "allow stripe.support\n");
                json!({"kind":"ok","view":{
                    "canonical_text":"allow stripe.support@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
                    "canonical_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "rule_count":1,
                    "set_snapshots":[{"rule_index":0,"provider":"stripe","set":"support","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","members":["refund"]}]
                }})
            }
            CtlRequest::SentenceAuthorityStatus => json!({"kind":"ok","view":{
                "sentence":{"state":"Absent"},
                "lockdown":"engaged"
            }}),
            _ => json!({"kind":"error","code":"internal","reason":"unexpected"}),
        },
        2,
    );
    let client = CtlBrokerClient::new(path, this_uid());
    let prepared = client
        .prepare_sentences("allow stripe.support\n".into())
        .await
        .unwrap();
    assert_eq!(prepared.rule_count, 1);
    assert_eq!(prepared.set_snapshots[0].members, ["refund"]);
    let status = client.sentence_authority_status().await.unwrap();
    assert_eq!(status.sentence, cermet_ipc::ctl::SentenceSnapshot::Absent);
    assert_eq!(status.lockdown, cermet_ipc::ctl::LockdownSnapshot::Engaged);
    server.join().unwrap();
}

#[tokio::test]
async fn read_artifact_returns_the_span_view_on_ok() {
    // The console/CLI artifact read forwards over ctl and returns the span JSON verbatim.
    let (_d, path, srv) = stub(
        |req| match req {
            CtlRequest::ReadArtifact { handle, .. } => {
                assert_eq!(handle, "art_1");
                json!({"kind":"ok","view":{"handle":"art_1","content":"line one\nline two"}})
            }
            _ => json!({"kind":"error","code":"internal","reason":"unexpected"}),
        },
        1,
    );
    let r = CtlBrokerClient::new(path, this_uid())
        .read_artifact("art_1".into(), None, None)
        .await
        .expect("ok");
    assert!(
        r.contains("line one"),
        "the span view is returned verbatim: {r}"
    );
    srv.join().unwrap();
}

#[tokio::test]
async fn read_artifact_maps_not_found_to_404_class_no_oracle() {
    // Fail closed: the daemon collapses unknown/tampered/missing to `not_found`; the client must
    // surface Error::NotFound (→ 404) with no distinction between failure classes.
    let (_d, path, srv) = stub(
        |_| json!({"kind":"error","code":"not_found","reason":"artifact unavailable"}),
        1,
    );
    let err = CtlBrokerClient::new(path, this_uid())
        .read_artifact("art_ghost".into(), None, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::NotFound(_)),
        "unknown handle fails closed as 404: {err:?}"
    );
    srv.join().unwrap();
}

#[tokio::test]
async fn maps_error_codes_to_core_variants_preserving_status() {
    // Each code -> the cermet_core::Error variant whose ApiError status the HTTP layer needs.
    for (code, want_denied, want_notfound, want_invalid, want_disabled) in [
        ("denied", true, false, false, false),
        ("provider_disabled", false, false, false, true),
        ("not_found", false, true, false, false),
        ("invalid", false, false, true, false),
        ("internal", false, false, false, false), // -> Provider -> 500
    ] {
        let code_s = code.to_string();
        let (_d, path, srv) = stub(
            move |_| json!({"kind":"error","code":code_s,"reason":"boom"}),
            1,
        );
        let err = CtlBrokerClient::new(path, this_uid())
            .history()
            .await
            .unwrap_err();
        assert_eq!(
            matches!(err, Error::Denied(_)),
            want_denied,
            "code={code} -> {err:?}"
        );
        assert_eq!(
            matches!(err, Error::NotFound(_)),
            want_notfound,
            "code={code} -> {err:?}"
        );
        assert_eq!(
            matches!(err, Error::Invalid(_)),
            want_invalid,
            "code={code} -> {err:?}"
        );
        assert_eq!(
            matches!(err, Error::ProviderDisabled),
            want_disabled,
            "code={code} -> {err:?}"
        );
        srv.join().unwrap();
    }
}

#[tokio::test]
async fn rejects_ok_envelope_without_view_fail_closed() {
    // Closure at the app boundary: kind:ok with no view is NOT a silent empty success.
    let (_d, path, srv) = stub(|_| json!({"kind":"ok"}), 1);
    let err = CtlBrokerClient::new(path, this_uid())
        .history()
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::Provider(_)),
        "missing view fails closed: {err:?}"
    );
    srv.join().unwrap();
}

#[tokio::test]
async fn connect_transmits_the_token_to_the_daemon_redacted_in_debug() {
    let (_d, path, srv) = stub(
        |req| match req {
            CtlRequest::Connect {
                token, provider, ..
            } => {
                assert_eq!(
                    token.0, "tok_secret",
                    "the daemon receives the raw token to vault it"
                );
                assert_eq!(provider, "vercel");
                // The wrapper never spills the token via Debug, even server-side.
                assert!(
                    !format!("{req:?}").contains("tok_secret"),
                    "Debug stays redacted"
                );
                json!({"kind":"ok","view":{"stored":true,"provider":"vercel"}})
            }
            _ => json!({"kind":"error","code":"internal","reason":"unexpected"}),
        },
        1,
    );
    let r = CtlBrokerClient::new(path, this_uid())
        .connect(
            "vercel".into(),
            SecretString::new("tok_secret".into()),
            None,
        )
        .await
        .expect("connect ok");
    assert!(
        r.contains("stored"),
        "connect returns the secret-free outcome view: {r}"
    );
    srv.join().unwrap();
}

#[tokio::test]
async fn a_wedged_daemon_times_out_instead_of_hanging() {
    // Server accepts then holds the connection open WITHOUT replying. A short client timeout must
    // turn this into an error rather than a forever-hang (the footgun at the usage site).
    let dir = tempdir().unwrap();
    // Harden the runtime dir (0o700) AND the socket mode (0o660) so the client gets PAST
    // keyholder verification (dir-contract + inode) and actually exercises the wedged-read
    // timeout (not a verification rejection).
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("ctl.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
    // Detached: never joined, so the test ends as soon as the client times out.
    let _wedged = thread::spawn(move || {
        let (_conn, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(5)); // hold open; never write
    });
    let client = CtlBrokerClient::with_timeout(path, this_uid(), Duration::from_millis(200));
    let err = client.history().await.unwrap_err();
    assert!(
        matches!(err, Error::Provider(_)),
        "a wedged daemon yields a Provider error: {err:?}"
    );
}

#[tokio::test]
async fn verify_boot_accepts_a_serving_daemon() {
    // The boot handshake sends `Doctor` and accepts only a live daemon —
    // kind=="doctor" AND serving==true. A serving daemon (bound at the real 0o660) passes.
    let (_d, path, srv) = stub(
        |req| match req {
            CtlRequest::Doctor => json!({"kind":"doctor","serving":true,"checks":[]}),
            _ => json!({"kind":"error","code":"internal","reason":"unexpected"}),
        },
        1,
    );
    let client = CtlBrokerClient::new(path, this_uid());
    client
        .verify_boot()
        .await
        .expect("a serving daemon passes the boot handshake");
    srv.join().unwrap();
}

#[tokio::test]
async fn verify_boot_rejects_a_non_serving_daemon() {
    // serving:false means the daemon is up but refusing to serve (fail closed) — the boot
    // handshake must NOT let cermet-app bind its listener and then 500 on every call.
    let (_d, path, srv) = stub(
        |req| match req {
            CtlRequest::Doctor => json!({"kind":"doctor","serving":false,"checks":[]}),
            _ => json!({"kind":"error","code":"internal","reason":"unexpected"}),
        },
        1,
    );
    let client = CtlBrokerClient::new(path, this_uid());
    let err = client.verify_boot().await.unwrap_err();
    assert!(
        matches!(err, Error::Provider(_)),
        "serving:false fails the boot handshake: {err:?}"
    );
    srv.join().unwrap();
}

#[tokio::test]
async fn verify_boot_rejects_an_error_envelope() {
    // Any non-doctor / error response (a misconfigured or impostor endpoint) fails the handshake.
    let (_d, path, srv) = stub(
        |_| json!({"kind":"error","code":"internal","reason":"boom"}),
        1,
    );
    let client = CtlBrokerClient::new(path, this_uid());
    assert!(
        client.verify_boot().await.is_err(),
        "an error envelope fails the boot handshake",
    );
    srv.join().unwrap();
}

#[tokio::test]
async fn rejects_a_socket_failing_inode_verification_before_sending() {
    // Per-connection keyholder verification must run BEFORE the client writes any byte —
    // most importantly the raw provider token in `connect()`. A socket bound 0o600 (NOT the
    // daemon's EXACT 0o660) is an impostor inode and must be refused before the first frame.
    //
    // We bind 0o600 and have the acceptor RECORD every frame it receives. The proof of safety is
    // not just the Err — it is that the recorder stays EMPTY: the client rejected the socket
    // before sending, so nothing (no token) could leak to a non-keyholder. Pre-fix the client
    // connects-then-writes, so the recorder sees one frame and this test is RED.
    let dir = tempdir().unwrap();
    // Harden the dir (0o700) so the dir-contract passes and the INODE mode (0o600, not the
    // daemon's exact 0o660) is the check that rejects — isolating inode verification.
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("ctl.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

    let received: Arc<Mutex<Vec<CtlRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&received);
    // Detached recording acceptor: log any frame the client sends. If the client rejects the
    // socket before writing, `read_frame` sees EOF and records nothing.
    let _acc = thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            if let Ok(req) = read_frame::<_, CtlRequest>(&mut conn) {
                recorder.lock().unwrap().push(req);
            }
        }
    });

    let client = CtlBrokerClient::with_timeout(path, this_uid(), Duration::from_secs(2));
    let err = client.history().await.unwrap_err();
    assert!(
        matches!(err, Error::Provider(_)),
        "a socket that fails inode verification is refused: {err:?}"
    );
    assert_eq!(
            received.lock().unwrap().len(),
            0,
            "verification MUST reject before writing any frame — no request/token may reach an impostor"
        );
}

#[tokio::test]
async fn rejects_a_socket_outside_the_trusted_runtime_dir() {
    // The trust anchor is the launcher-passed `expected_daemon_uid`, AND the on-disk
    // runtime-dir contract is defense-in-depth. A 0o660 socket owned by getuid() that LOOKS
    // authentic at the inode level can sit in a world-writable (0o777) parent dir — i.e. NOT a
    // hardened daemon runtime dir (0o700 or setgid-0o2711, not other-writable). This is the
    // `CERMET_CTL_SOCK=/tmp/evil/ctl.sock` worked example: an attacker-traversable dir. The
    // client MUST reject it BEFORE writing any byte — most importantly the raw provider token in
    // `connect()`. Proof of safety is the recorder staying EMPTY. Pre-fix, verify ignores the
    // parent dir, so the client connects-then-writes and the recorder sees one frame → RED.
    let dir = tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let path = dir.path().join("ctl.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();

    let received: Arc<Mutex<Vec<CtlRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&received);
    let _acc = thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            if let Ok(req) = read_frame::<_, CtlRequest>(&mut conn) {
                recorder.lock().unwrap().push(req);
            }
        }
    });

    // expected_daemon_uid = getuid(): the inode owner/mode/peer all match, so ONLY the
    // dir-contract can reject this. That isolates the defense-in-depth check.
    let client = CtlBrokerClient::with_timeout(path, this_uid(), Duration::from_secs(2));
    let err = client.history().await.unwrap_err();
    assert!(
        matches!(err, Error::Provider(_)),
        "a socket in a non-hardened (world-writable) runtime dir is refused: {err:?}"
    );
    assert_eq!(
        received.lock().unwrap().len(),
        0,
        "the runtime-dir contract MUST reject before any frame is written — no token may reach \
             an attacker-owned socket on a hostile env path"
    );
}

#[tokio::test]
async fn rejects_when_peer_is_not_the_expected_daemon_uid() {
    // Trust anchor: `expected_daemon_uid` is launcher-passed; an attacker cannot set
    // uid-501's launch env. So a real getuid()-owned 0o660 socket in a properly hardened 0700
    // dir (tempfile::tempdir is 0700-owned-by-getuid) is self-consistent and would pass the
    // legacy inode check — but the CONNECTED peer uid (getuid) is NOT the expected daemon uid
    // (getuid()+1). The client MUST refuse before writing any frame. Pre-fix there is no
    // expected-uid binding at all, so the client writes and the recorder sees a frame → RED.
    let dir = tempdir().unwrap(); // 0700, owned by getuid — a hardened runtime dir
    let path = dir.path().join("ctl.sock");
    let listener = UnixListener::bind(&path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();

    let received: Arc<Mutex<Vec<CtlRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&received);
    let _acc = thread::spawn(move || {
        if let Ok((mut conn, _)) = listener.accept() {
            if let Ok(req) = read_frame::<_, CtlRequest>(&mut conn) {
                recorder.lock().unwrap().push(req);
            }
        }
    });

    // Expect a DIFFERENT daemon uid than the actual peer (getuid()). u32 wraps harmlessly at
    // u32::MAX; getuid() is never u32::MAX in practice, so +1 is always a mismatch.
    let wrong_expected = this_uid().wrapping_add(1);
    let client = CtlBrokerClient::with_timeout(path, wrong_expected, Duration::from_secs(2));
    let err = client.history().await.unwrap_err();
    assert!(
        matches!(err, Error::Provider(_)),
        "a peer whose uid is not the expected daemon uid is refused: {err:?}"
    );
    assert_eq!(
        received.lock().unwrap().len(),
        0,
        "an unexpected-peer-uid socket MUST be rejected before any frame is written"
    );
}

/// The client rebuilds the typed error from the wire pair (`code` = class, `reason` =
/// bare payload) and renders the class prefix exactly once. Every class the daemon can frame has a
/// code, so no class collapses into the fail-safe `Provider` on the way back.
#[test]
fn error_envelope_rebuilds_every_class_and_renders_it_once() {
    let cases = [
        (
            "denied",
            "no rule matches this request",
            "capability denied: no rule matches this request",
        ),
        (
            "not_found",
            "req_cdd141a4690581c1",
            "not found: req_cdd141a4690581c1",
        ),
        (
            "invalid",
            "resource is not an object",
            "invalid input: resource is not an object",
        ),
        (
            "integrity",
            "grant integrity failed",
            "integrity error: grant integrity failed",
        ),
        (
            "crypto",
            "vault open failed",
            "crypto error: vault open failed",
        ),
        (
            "execute_refused",
            "grant already used (single-use)",
            "execute refused: grant already used (single-use)",
        ),
        ("session_expired", "session expired", "session expired"),
        (
            "provider_disabled",
            "provider_disabled",
            "provider_disabled",
        ),
        // The fail-safe class: an unknown/internal code is a provider error, prefixed once.
        (
            "internal",
            "stripe returned 500",
            "provider error: stripe returned 500",
        ),
    ];
    for (code, reason, rendered) in cases {
        let error = error_from_envelope(&json!({"kind":"error","code":code,"reason":reason}));
        assert_eq!(error.to_string(), rendered, "code {code} rendered wrong");
    }
}

// ---- Build skew on the operator channel --------------------------------------------------------

#[tokio::test]
async fn a_daemon_on_this_build_is_never_remarked_on() {
    assert_eq!(
        build_skew_note(&json!({"kind":"ok","view":[],"build": cermet_ipc::BUILD_ID})),
        None
    );
}

#[tokio::test]
async fn a_daemon_on_another_build_is_named_once_with_the_command_that_fixes_it() {
    let note = build_skew_note(&json!({"kind":"ok","view":[],"build":"0.0.1+deadbeef"}))
        .expect("a skew is worth a line");
    assert!(note.contains("0.0.1+deadbeef"), "names the daemon: {note}");
    assert!(note.contains(cermet_ipc::BUILD_ID), "and this CLI: {note}");
    assert!(note.contains("make -C dist install"), "and the fix: {note}");
}

#[tokio::test]
async fn a_daemon_predating_the_build_stamp_reads_as_unknown() {
    let note = build_skew_note(&json!({"kind":"ok","view":[]})).expect("absence is still skew");
    assert!(note.contains("unknown"), "{note}");
}
