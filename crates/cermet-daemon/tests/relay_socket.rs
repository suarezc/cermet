//! The loopback relay listener, over real HTTP, end to end.
//!
//! This is the leg the core's unit tests cannot cover: a real HTTP/1.1 request off a real socket, the
//! hyper adapter, the broker actor, the credentialed hop to a real (mock) upstream, and the response
//! written back. The native `vercel` CLI is the real client; here the client is raw HTTP, which is
//! what the CLI is underneath.
//!
//! Adversaries: T3 (a peer uid connecting to the port with no handle → 409, "no live relay session"),
//! T1/T2 (a request outside the ratified predicate → 422 with the credential never attached). Neither
//! is an auth status: the identity is fine, the capability is spent or the request is outside it, and
//! a native client renders 401/403 as a login failure.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

use cermet_broker_actor::{spawn_full, BrokerHandle};
use cermet_core::{BrokerConfig, RelayConfig, SentenceAuthoritySource};
use secrecy::SecretString;
use serde_json::{json, Value};
use tempfile::tempdir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const RELAY_TOKEN: &str = "vercel_tok_NEVER_ON_THE_LOOPBACK_WIRE";

struct RelaySentenceAuthority(cermet_core::sentence::RuleSet);

impl SentenceAuthoritySource for RelaySentenceAuthority {
    fn current_authority(
        &self,
    ) -> cermet_core::Result<cermet_core::AuthenticatedSentenceAuthority> {
        Ok(cermet_core::AuthenticatedSentenceAuthority {
            digest: cermet_core::sentence::authority_digest(&self.0),
            rules: self.0.clone(),
        })
    }
}

/// A broker whose vercel descriptor points at `upstream`, with the relay bound to an ephemeral
/// loopback port (the listen authority is a declared setting, so the test declares it).
fn relay_broker(dir: &Path, upstream: &str, listen: &str) -> BrokerHandle {
    relay_broker_ttl(dir, upstream, listen, 600)
}

fn relay_broker_ttl(dir: &Path, upstream: &str, listen: &str, ttl_secs: u64) -> BrokerHandle {
    let descriptors = BrokerConfig::vendored_descriptors()
        .into_iter()
        .filter(|descriptor| !descriptor.contains("name: vercel\n"))
        .chain([format!(
            "name: vercel\negress:\n  - {upstream}\nauth: bearer\n"
        )])
        .collect();
    let mut rules = cermet_core::sentence::parse_rules(
        "allow vercel.deploy where project = \"website\" and team = \"personal\"",
    )
    .unwrap();
    cermet_core::sentence::pin_set_references(&mut rules, &cermet_core::sets::VendoredSetResolver)
        .unwrap();
    spawn_full(
        BrokerConfig {
            git: cermet_core::git::GitConfig::at(dir.join("cermet-test-quarantine")),
            dir: dir.to_path_buf(),
            master_key: vec![9u8; 32],
            action_templates: cermet_core::templates::VENDORED_CATALOG
                .iter()
                .map(|source| source.to_string())
                .collect(),
            provider_descriptors: descriptors,
            artifacts: cermet_core::ArtifactConfig::default(),
        },
        Vec::new(),
        Some(std::sync::Arc::new(RelaySentenceAuthority(rules))),
        None,
        None,
        Some(RelayConfig {
            listen: listen.to_string(),
            ttl_secs,
            max_body_bytes: 4096,
        }),
        None,
    )
    .expect("the broker opens")
}

/// One HTTP/1.1 request over a fresh connection; returns (status, headers-lowercased, body).
fn http(addr: &str, request: &str, body: &[u8]) -> (u16, String, String) {
    let mut stream = TcpStream::connect(addr).expect("the relay accepts a loopback connection");
    let mut bytes = request.as_bytes().to_vec();
    bytes.extend_from_slice(body);
    stream.write_all(&bytes).unwrap();
    stream.flush().unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or_else(|| panic!("no status line in: {text}"));
    let (headers, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (status, headers.to_lowercase(), body.to_string())
}

fn get(handle: &str, target: &str) -> String {
    format!(
        "GET {target} HTTP/1.1\r\nHost: relay\r\nAuthorization: Bearer {handle}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
    )
}

fn post(handle: &str, target: &str, body: &str) -> String {
    format!(
        "POST {target} HTTP/1.1\r\nHost: relay\r\nAuthorization: Bearer {handle}\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
}

/// Request -> allow -> execute, returning the minted handle and the receipt.
async fn open_relay(broker: &BrokerHandle) -> (String, Value) {
    let outcome: Value = serde_json::from_str(
        &broker
            .request(
                "s1".into(),
                json!({
                    "provider": "vercel",
                    "action": "deploy",
                    "resource": { "project": "website", "target": "preview", "team": "personal" }
                })
                .to_string(),
                None,
                None,
            )
            .await
            .expect("the allow admits the request"),
    )
    .unwrap();
    // The operator execute is addressed by the ONE public id.
    let request_id = outcome["request_id"]
        .as_str()
        .expect("every request outcome names its request id")
        .to_string();
    let receipt: Value = serde_json::from_str(
        &broker
            .execute_operator(request_id)
            .await
            .expect("executing a relay verb opens its session"),
    )
    .unwrap();
    let handle = receipt["result"]["relay"]["handle"]
        .as_str()
        .expect("the receipt names the handle")
        .to_string();
    (handle, receipt)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_loopback_relay_credentials_a_declared_hop_and_refuses_everything_else() {
    let upstream = MockServer::start().await;
    // The upstream asserts what the relay attached: the VAULTED credential, never the handle.
    Mock::given(method("POST"))
        .and(path("/v13/deployments"))
        .and(header("authorization", &*format!("Bearer {RELAY_TOKEN}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "dpl_e2e",
            "url": "website-e2e.vercel.app",
            "name": "website",
            "readyState": "QUEUED"
        })))
        .mount(&upstream)
        .await;

    let dir = tempdir().unwrap();
    let broker = relay_broker(dir.path(), &upstream.uri(), "127.0.0.1:0");
    broker
        .connect("vercel".into(), SecretString::new(RELAY_TOKEN.into()), None)
        .await
        .expect("the operator connects a vercel credential");

    // The listener binds an ephemeral port; the receipt's api_base is what the agent is told to use.
    let addr = cermet_daemon::relay::serve(
        RelayConfig {
            listen: "127.0.0.1:0".into(),
            ttl_secs: 600,
            max_body_bytes: 4096,
        },
        broker.clone(),
    )
    .await
    .expect("the relay binds")
    .expect("the relay is enabled");
    let addr = addr.to_string();

    let (handle, receipt) = open_relay(&broker).await;
    assert!(
        !receipt.to_string().contains(RELAY_TOKEN),
        "the execute receipt never carries the credential"
    );

    // A declared hop: the deployment create of the pinned project.
    let (status, _headers, body) = http(
        &addr,
        &post(&handle, "/v13/deployments", r#"{"name":"website"}"#),
        br#"{"name":"website"}"#,
    );
    assert_eq!(status, 200, "a declared hop is forwarded: {body}");
    assert!(
        body.contains("dpl_e2e"),
        "the provider body comes back: {body}"
    );
    assert!(
        !body.contains(RELAY_TOKEN),
        "no client-facing byte carries the credential: {body}"
    );

    // T3: a peer uid can reach the port but has no handle.
    for wrong in ["", "notarealhandle", &handle.to_lowercase()] {
        if wrong == handle {
            continue;
        }
        let (status, _headers, body) = http(&addr, &get(wrong, "/v13/deployments/dpl_e2e"), b"");
        assert_eq!(status, 409, "an unknown handle is refused: {body}");
        assert!(
            body.contains("cermet: no live relay session"),
            "the refusal states the truth in the field the native CLI prints: {body}"
        );
        assert!(!body.contains(&handle) && !body.contains(RELAY_TOKEN));
    }
    // ...and a request with no Authorization header at all.
    let (status, _headers, _body) = http(
        &addr,
        "GET /v13/deployments/dpl_e2e HTTP/1.1\r\nHost: relay\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        b"",
    );
    assert_eq!(status, 409, "no bearer, no relay");

    // T1: the same session, an undeclared shape. The upstream has no matcher for it, so if the relay
    // ever forwarded it the assertion below would see a 404 from wiremock instead of the refusal.
    let (status, _headers, _body) = http(&addr, &get(&handle, "/v9/projects/website/env"), b"");
    assert_eq!(status, 422, "an undeclared shape is refused, not forwarded");

    // The refusal burned the session: even the declared read is now an unknown handle.
    let (status, _headers, _body) = http(&addr, &get(&handle, "/v13/deployments/dpl_e2e"), b"");
    assert_eq!(status, 409);

    // Exactly one request reached the provider, and the audit chain still verifies.
    assert_eq!(
        upstream.received_requests().await.unwrap().len(),
        1,
        "only the declared hop was ever credentialed"
    );
    let integrity: Value =
        serde_json::from_str(&broker.verify_audit().await.expect("audit verifies")).unwrap();
    assert_eq!(integrity["verified"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn an_oversized_body_is_refused_by_the_declared_cap() {
    let upstream = MockServer::start().await;
    let dir = tempdir().unwrap();
    let broker = relay_broker(dir.path(), &upstream.uri(), "127.0.0.1:0");
    let addr = cermet_daemon::relay::serve(
        RelayConfig {
            listen: "127.0.0.1:0".into(),
            ttl_secs: 600,
            max_body_bytes: 64,
        },
        broker.clone(),
    )
    .await
    .expect("the relay binds")
    .expect("the relay is enabled")
    .to_string();

    let body = "x".repeat(4096);
    let (status, _headers, _body) = http(
        &addr,
        &post("someHandle123456789012", "/v2/files", &body),
        body.as_bytes(),
    );
    assert_eq!(
        status, 413,
        "the declared body cap bounds what the relay will buffer"
    );
    assert!(
        upstream.received_requests().await.unwrap().is_empty(),
        "nothing reached the provider"
    );
}

/// A raw HTTP/1.1 upstream that answers ONE request with a CHUNKED body: the first chunk goes out
/// immediately, the last one only after the test releases the returned gate. That is exactly the
/// shape of the `follow=1` build-log read — a response whose head lands seconds before its last byte
/// — and the shape a buffering relay turns into a blind wait.
fn chunked_upstream(
    first: &'static str,
    last: &'static str,
) -> (
    String,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        );
        let _ = stream.write_all(format!("{:x}\r\n{first}\r\n", first.len()).as_bytes());
        let _ = stream.flush();
        // The upstream holds the rest open until the test has PROVEN the first chunk arrived.
        let _ = gate_rx.recv();
        let _ = stream.write_all(format!("{:x}\r\n{last}\r\n0\r\n\r\n", last.len()).as_bytes());
        let _ = stream.flush();
    });
    (format!("http://{addr}"), gate_tx, handle)
}

/// Read from `stream` until `needle` shows up, or the read timeout lapses. Returns everything read.
fn read_until(stream: &mut TcpStream, needle: &str) -> Result<String, String> {
    let mut text = String::new();
    let mut buf = [0u8; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => return Err(format!("upstream closed before `{needle}`: {text}")),
            Ok(n) => {
                text.push_str(&String::from_utf8_lossy(&buf[..n]));
                if text.contains(needle) {
                    return Ok(text);
                }
            }
            Err(error) => return Err(format!("read for `{needle}` failed ({error}): {text}")),
        }
    }
}

/// A streaming upstream must reach the native client AS IT ARRIVES. Otherwise the CLI's `follow=1`
/// build-log hop sits blind for minutes because the adapter buffers the whole body first; the CLI
/// only hangs up early when it can SEE the ready line.
#[tokio::test(flavor = "multi_thread")]
async fn a_streaming_hop_reaches_the_client_before_the_upstream_finishes() {
    let (upstream, gate, server) = chunked_upstream("first-log-line\n", "READY\n");
    let dir = tempdir().unwrap();
    let broker = relay_broker(dir.path(), &upstream, "127.0.0.1:0");
    broker
        .connect("vercel".into(), SecretString::new(RELAY_TOKEN.into()), None)
        .await
        .expect("the operator connects a vercel credential");
    let addr = cermet_daemon::relay::serve(
        RelayConfig {
            listen: "127.0.0.1:0".into(),
            ttl_secs: 600,
            max_body_bytes: 4096,
        },
        broker.clone(),
    )
    .await
    .expect("the relay binds")
    .expect("the relay is enabled")
    .to_string();

    let (handle, _receipt) = open_relay(&broker).await;
    // A declared read that carries no `path.*` bind: this test is about the SOCKET
    // handing back a head while the upstream still writes, not about the deployment dataflow, which
    // the core suite covers on the events path itself.
    let request = get(&handle, "/v9/projects/website");

    let (arrived, first_chunk) = tokio::sync::oneshot::channel::<()>();
    let client = tokio::task::spawn_blocking(move || {
        let mut stream =
            TcpStream::connect(&addr).expect("the relay accepts a loopback connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.flush().unwrap();
        // The whole point: this must return while the upstream is still holding the body open.
        let head = read_until(&mut stream, "first-log-line")?;
        let _ = arrived.send(());
        let tail = read_until(&mut stream, "READY")?;
        Ok::<(String, String), String>((head, tail))
    });

    tokio::time::timeout(Duration::from_secs(5), first_chunk)
        .await
        .expect("the first chunk arrives before the upstream finishes")
        .expect("the client task is alive");
    // ...and the in-flight stream does NOT own the broker actor. If it did, deny-all would be
    // unreachable for as long as a build-log follow runs — which is minutes.
    tokio::time::timeout(Duration::from_secs(5), broker.sweep_relay_sessions())
        .await
        .expect("the broker actor answers while a hop is still streaming");

    gate.send(()).expect("the upstream is still waiting");
    let (head, _tail) = client
        .await
        .expect("the client task does not panic")
        .expect("the rest of the stream arrives");
    server.join().unwrap();
    let lower = head.to_lowercase();
    assert!(lower.starts_with("http/1.1 200"), "{head}");
    assert!(
        lower.contains("transfer-encoding: chunked"),
        "a streamed body of unknown length is framed chunked: {head}"
    );
    assert!(
        !lower.contains("content-length:"),
        "a chunked response must not also declare a length: {head}"
    );
    assert!(
        !head.contains(RELAY_TOKEN),
        "no client byte carries the credential"
    );

    let integrity: Value =
        serde_json::from_str(&broker.verify_audit().await.expect("audit verifies")).unwrap();
    assert_eq!(integrity["verified"], true);
}

/// An upstream that completes the TCP handshake, reads the request, and then sends NOTHING. It is
/// the shape that used to deafen every relay socket: time-to-first-byte ran on the broker actor.
fn silent_head_upstream() -> (
    String,
    std::sync::mpsc::Sender<()>,
    std::thread::JoinHandle<()>,
) {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();
    let handle = std::thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf);
        // Hold the connection open, and silent, until the test is done with it.
        let _ = stop_rx.recv();
    });
    (format!("http://{addr}"), stop_tx, handle)
}

/// The broker actor must never touch the network. An upstream that handshakes and then
/// goes silent must not block a single other broker call, and the hop must die at its own head bound
/// with the client told the upstream was unavailable.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_upstream_never_holds_the_broker_actor() {
    let (upstream, stop, server) = silent_head_upstream();
    let dir = tempdir().unwrap();
    // The head bound is the session's own TTL when that is shorter than the 30 s ceiling, so a
    // short-TTL session gives a short-lived hop — no new setting, and the test does not sit for 30 s.
    let ttl_secs = 3;
    let broker = relay_broker_ttl(dir.path(), &upstream, "127.0.0.1:0", ttl_secs);
    broker
        .connect("vercel".into(), SecretString::new(RELAY_TOKEN.into()), None)
        .await
        .expect("the operator connects a vercel credential");
    let addr = cermet_daemon::relay::serve(
        RelayConfig {
            listen: "127.0.0.1:0".into(),
            ttl_secs,
            max_body_bytes: 4096,
        },
        broker.clone(),
    )
    .await
    .expect("the relay binds")
    .expect("the relay is enabled")
    .to_string();

    let (handle, _receipt) = open_relay(&broker).await;
    let request = get(&handle, "/v9/projects/website");
    let client = tokio::task::spawn_blocking(move || {
        let mut stream =
            TcpStream::connect(&addr).expect("the relay accepts a loopback connection");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        stream.write_all(request.as_bytes()).unwrap();
        stream.flush().unwrap();
        let mut response = Vec::new();
        let _ = stream.read_to_end(&mut response);
        String::from_utf8_lossy(&response).into_owned()
    });

    // The hop is in flight against a dead-silent upstream. The broker must answer anyway — deny-all
    // and every other caller run through this same actor.
    tokio::time::sleep(Duration::from_millis(250)).await;
    for _ in 0..3 {
        tokio::time::timeout(Duration::from_secs(1), broker.sweep_relay_sessions())
            .await
            .expect("the broker actor answers while a hop waits on a silent upstream");
    }

    // ...and the hop itself gives up at its own bound rather than hanging on forever.
    let response = tokio::time::timeout(Duration::from_secs(20), client)
        .await
        .expect("the hop gives up at the head bound")
        .expect("the client task does not panic");
    stop.send(()).ok();
    server.join().unwrap();
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "a hop that never got a head is an upstream failure: {response}"
    );
    let integrity: Value =
        serde_json::from_str(&broker.verify_audit().await.expect("audit verifies")).unwrap();
    assert_eq!(integrity["verified"], true);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_disabled_relay_binds_nothing() {
    let upstream = MockServer::start().await;
    let dir = tempdir().unwrap();
    let broker = relay_broker(dir.path(), &upstream.uri(), "");
    let bound = cermet_daemon::relay::serve(
        RelayConfig {
            listen: String::new(),
            ..RelayConfig::default()
        },
        broker,
    )
    .await
    .expect("a disabled relay is not an error");
    assert!(bound.is_none(), "relay_listen = \"\" opens no door at all");
}
