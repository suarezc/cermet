//! Hermetic proof through production operator, agent, broker, recovery, and owner seams.

use std::io::Write;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use cermet_core::BrokerConfig;
use cermet_ctl_client::broker_client::CtlBrokerClient;
use cermet_ctl_client::presence::{Presence, PresenceOutcome};
use cermet_daemon::lockdown::LockdownStore;
use cermet_daemon::sentence_record::SentenceRecordAdmin;
use cermet_ipc::owner::{OwnerRequest, OwnerResponse};
use cermet_ipc::wire::AgentRequest;
use serde_json::{json, Value};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

mod common;

const FIXTURE_DAEMON_UID: u32 = 999_001;
const FAKE_STRIPE_TOKEN: &str = "sk_test_m5_hermetic_only";

#[derive(Default)]
struct CountingPresence(AtomicUsize);

impl CountingPresence {
    fn count(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl Presence for CountingPresence {
    fn confirm(&self, _reason: &str) -> PresenceOutcome {
        self.0.fetch_add(1, Ordering::SeqCst);
        PresenceOutcome::Confirmed
    }
}

struct RunningDaemon {
    client: CtlBrokerClient,
    socket: PathBuf,
    agent_socket: PathBuf,
    owner_socket: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

struct AgentSession {
    stream: UnixStream,
    session_id: String,
}

impl AgentSession {
    fn connect(socket: &Path) -> Self {
        let mut stream = UnixStream::connect(socket).unwrap();
        cermet_ipc::codec::write_frame(
            &mut stream,
            &AgentRequest::Hello {
                agent: "hermetic".to_string(),
                build: cermet_ipc::BUILD_ID.to_string(),
                client_name: None,
                client_version: None,
                model: None,
            },
        )
        .unwrap();
        let hello: Value = cermet_ipc::codec::read_response_frame(&mut stream).unwrap();
        assert_eq!(hello["kind"], "session", "{hello}");
        let session_id = hello["session_id"]
            .as_str()
            .expect("Hello returns the production session handle")
            .to_string();
        assert!(session_id.starts_with("sess_"), "{hello}");
        assert!(
            hello["features"]
                .as_array()
                .is_some_and(|features| features.iter().any(|feature| {
                    feature.as_str() == Some(cermet_ipc::wire::FEATURE_ASYNC_EXECUTE)
                })),
            "Hello must negotiate the production agent protocol: {hello}"
        );
        Self { stream, session_id }
    }

    fn call(&mut self, mut request: AgentRequest) -> Value {
        request.set_session_id(Some(self.session_id.clone()));
        cermet_ipc::codec::write_frame(&mut self.stream, &request).unwrap();
        cermet_ipc::codec::read_response_frame(&mut self.stream).unwrap()
    }

    fn request(&mut self, provider: &str, action: &str, resource: Value) -> Value {
        self.call(AgentRequest::Request {
            provider: provider.to_string(),
            action: action.to_string(),
            resource,
            environment: None,
            justification: Some("hermetic lifecycle proof".to_string()),
            model: None,
            retry_effect: None,
            session_id: None,
        })
    }

    fn execute(&mut self, request_id: &str) -> Value {
        self.call(AgentRequest::Execute {
            request_id: request_id.to_string(),
            session_id: None,
        })
    }

    fn artifact(&mut self, handle: &str) -> Value {
        self.call(AgentRequest::Artifact {
            handle: handle.to_string(),
            range: None,
            path: None,
            session_id: None,
        })
    }

    fn status(&mut self, request_id: &str) -> Value {
        self.call(AgentRequest::Status {
            request_id: request_id.to_string(),
            session_id: None,
        })
    }

    fn verify_audit(&mut self) -> Value {
        self.call(AgentRequest::VerifyAudit { session_id: None })
    }
}

impl RunningDaemon {
    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn start_daemon(runtime: &tokio::runtime::Runtime, state: &Path, boot: usize) -> RunningDaemon {
    let uid = nix::unistd::geteuid().as_raw();
    LockdownStore::initialize_clear(state, uid).unwrap();
    let lockdown = Arc::new(LockdownStore::new(state, uid));
    cermet_daemon::startup::adopt_lockdown(&lockdown);

    let record = cermet_daemon::sentence_record::build_record_store(state, None);
    let authority: Arc<dyn cermet_core::SentenceAuthoritySource> = record.clone();
    let broker = cermet_broker_actor::spawn_full(
        BrokerConfig {
            git: cermet_core::git::GitConfig::at(
                std::env::temp_dir().join("cermet-test-quarantine"),
            ),
            dir: state.to_path_buf(),
            master_key: vec![0x5a; 32],
            action_templates: cermet_core::templates::VENDORED_CATALOG
                .iter()
                .map(|source| source.to_string())
                .collect(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: cermet_core::ArtifactConfig::default(),
        },
        Vec::new(),
        Some(authority),
        Some(lockdown.clone()),
        None,
        None,
        None,
    )
    .unwrap();
    runtime.block_on(cermet_daemon::startup::recover_after_broker_start(
        &record, &lockdown, &broker,
    ));

    let runtime_dir = state.join(format!("run-{boot}"));
    std::fs::create_dir(&runtime_dir).unwrap();
    std::fs::set_permissions(
        &runtime_dir,
        std::os::unix::fs::PermissionsExt::from_mode(0o700),
    )
    .unwrap();
    let (ctl_listener, socket) = cermet_daemon::ctl::bind_ctl_socket(&runtime_dir).unwrap();
    let (owner_listener, owner_socket) =
        cermet_daemon::owner::bind_owner_socket(&runtime_dir).unwrap();
    let (agent_listener, agent_socket) =
        cermet_daemon::serve::bind_agent_socket(&runtime_dir).unwrap();
    ctl_listener.set_nonblocking(true).unwrap();
    owner_listener.set_nonblocking(true).unwrap();
    agent_listener.set_nonblocking(true).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let thread_record: Arc<dyn SentenceRecordAdmin> = record;
    let thread_lockdown: Arc<dyn cermet_core::LockdownSource> = lockdown.clone();
    let owner_lockdown = lockdown;
    let handle = runtime.handle().clone();
    let thread_home = state.to_path_buf();
    let thread_runtime = runtime_dir.clone();
    let owner_broker = broker.clone();
    let admitted_agent_uid = nix::unistd::geteuid().as_raw();
    let timeouts = cermet_daemon::serve::ServeTimeouts::default();
    let thread = std::thread::spawn(move || {
        while !thread_stop.load(Ordering::Acquire) {
            let mut handled = false;
            match ctl_listener.accept() {
                Ok((stream, _)) => {
                    handled = true;
                    // BSD accept() inherits the listener's O_NONBLOCK; Linux does not. The handlers
                    // below expect a blocking stream, so hand them one on both platforms.
                    stream.set_nonblocking(false).unwrap();
                    cermet_daemon::ctl::handle_ctl_connection(
                        stream,
                        &broker,
                        &handle,
                        nix::unistd::getuid().as_raw(),
                        FIXTURE_DAEMON_UID,
                        FIXTURE_DAEMON_UID,
                        &thread_home,
                        &thread_runtime,
                        &thread_runtime,
                        timeouts,
                        None,
                        None,
                        false,
                        None,
                        true,
                        &thread_record,
                        &thread_lockdown,
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("temporary ctl listener failed: {error}"),
            }
            match owner_listener.accept() {
                Ok((stream, _)) => {
                    handled = true;
                    stream.set_nonblocking(false).unwrap();
                    // The production peercred gate is separately pinned. This is the exact post-gate
                    // root stream handler used by the daemon after it authenticates uid 0.
                    cermet_daemon::owner::handle_root_owner_connection(
                        stream,
                        &owner_lockdown,
                        &owner_broker,
                        &handle,
                        timeouts,
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("temporary owner listener failed: {error}"),
            }
            match agent_listener.accept() {
                Ok((stream, _)) => {
                    handled = true;
                    stream.set_nonblocking(false).unwrap();
                    let connection_broker = broker.clone();
                    let connection_runtime = handle.clone();
                    std::thread::spawn(move || {
                        cermet_daemon::serve::handle_connection(
                            stream,
                            &connection_broker,
                            &connection_runtime,
                            "hermetic-agent",
                            Some(admitted_agent_uid),
                            timeouts,
                        );
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => panic!("temporary agent listener failed: {error}"),
            }
            if !handled {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
    });

    RunningDaemon {
        client: CtlBrokerClient::new(socket.clone(), nix::unistd::geteuid().as_raw()),
        socket,
        agent_socket,
        owner_socket,
        stop,
        thread: Some(thread),
    }
}

fn connect_stripe(daemon: &RunningDaemon, repo: &Path) {
    let mut child = Command::new(common::cermet_binary())
        .args(["connect", "stripe", "hermetic"])
        .current_dir(repo)
        .env("CERMET_CTL_SOCK", &daemon.socket)
        .env(
            "CERMET_DAEMON_UID",
            nix::unistd::geteuid().as_raw().to_string(),
        )
        .env_remove("STRIPE_TEST_KEY")
        .env_remove("STRIPE_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{FAKE_STRIPE_TOKEN}\n").as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(!String::from_utf8_lossy(&output.stdout).contains(FAKE_STRIPE_TOKEN));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(FAKE_STRIPE_TOKEN));
}

fn request_id(outcome: &Value) -> String {
    assert_eq!(outcome["kind"], "requested", "{outcome}");
    assert_eq!(outcome["decision"], "allow", "{outcome}");
    assert!(outcome.get("grant_id").is_none(), "{outcome}");
    outcome["request_id"].as_str().unwrap().to_string()
}

fn assert_redacted(frame: &Value, label: &str) {
    let captured = frame.to_string();
    assert!(
        captured.contains("[SECRET_REDACTED]"),
        "{label} lacks the credential redaction marker: {frame}"
    );
    assert!(
        !captured.contains(FAKE_STRIPE_TOKEN),
        "{label} exposed the raw provider credential: {frame}"
    );
}

fn authority(
    daemon: &RunningDaemon,
    repo: &Path,
    presence: Arc<CountingPresence>,
    arguments: &[&str],
) -> cermet_cli::AuthorityCommandOutput {
    let args = arguments
        .iter()
        .map(|arg| arg.to_string())
        .collect::<Vec<_>>();
    let command = cermet_cli::parse(&args).unwrap();
    cermet_cli::dispatch_authority_command(
        &daemon.client,
        &command,
        repo,
        &cermet_cli::tty::ScriptedTerminal::new(true, "", vec![true]),
        presence,
    )
    .unwrap()
    .expect("authority command")
}

fn hint_rule(outcome: &Value) -> String {
    let hint = outcome["hint"]
        .as_str()
        .expect("deny must carry widen hint");
    let quoted = hint
        .strip_prefix("to allow: cermet rules allow ")
        .expect("hint must be an executable cermet rules allow command");
    assert!(quoted.starts_with('\'') && quoted.ends_with('\''), "{hint}");
    quoted[1..quoted.len() - 1].replace("'\"'\"'", "'")
}

fn canonical_allow(argument: &str) -> String {
    if argument.starts_with("allow ") {
        argument.to_string()
    } else {
        format!("allow {argument}")
    }
}

fn rewrite_body(path: &Path, body: &str) {
    let bytes = std::fs::read(path).unwrap();
    let document = cermet_cli::cermet_document::ManagedDocument::parse(&bytes).unwrap();
    let source = String::from_utf8(bytes.clone()).unwrap();
    let prior = format!("```cermet\n{}```", document.body());
    let replacement = format!("```cermet\n{body}```");
    let rewritten = source.replacen(&prior, &replacement, 1);
    assert_ne!(rewritten, source, "managed body fence was not replaced");
    cermet_cli::cermet_document::ManagedDocument::parse(rewritten.as_bytes()).unwrap();
    std::fs::write(path, rewritten).unwrap();
}

fn owner_lockdown(daemon: &RunningDaemon) -> String {
    let mut stream = UnixStream::connect(&daemon.owner_socket).unwrap();
    cermet_ipc::codec::write_frame(&mut stream, &OwnerRequest::OwnerLockdown).unwrap();
    match cermet_ipc::codec::read_response_frame(&mut stream).unwrap() {
        OwnerResponse::Transitioned {
            engaged: true,
            occurrence_id,
        } => occurrence_id,
        response => panic!("unexpected owner response: {response:?}"),
    }
}

#[test]
fn hermetic_document_authority_lifecycle_covers_all_twelve_states() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let stripe = runtime.block_on(MockServer::start());
    runtime.block_on(
        Mock::given(method("POST"))
            .and(path("/v1/refunds"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "id": FAKE_STRIPE_TOKEN,
                "charge": "ch_beta",
                "amount": 2000,
                "status": "succeeded",
            })))
            .mount(&stripe),
    );
    std::env::set_var("CERMET_STRIPE_BASE_URL", stripe.uri());

    let state = tempfile::tempdir().unwrap();
    let repo = tempfile::tempdir().unwrap();
    std::fs::create_dir(repo.path().join(".git")).unwrap();
    let document_path = repo.path().join("CERMET.md");
    let presence = Arc::new(CountingPresence::default());
    let daemon = start_daemon(&runtime, state.path(), 1);
    connect_stripe(&daemon, repo.path());
    let mut agent = AgentSession::connect(&daemon.agent_socket);

    let help = Command::new(common::cermet_binary()).output().unwrap();
    let help = String::from_utf8(help.stderr).unwrap();
    // The corpus flow is carried by the `doc` noun itself, not by a legend under it.
    assert!(help.contains("doc check [--fix|--init]"), "{help}");
    assert!(help.contains("doc apply [--replace-live]"), "{help}");

    // 1. No record and no file is deny-all.
    let denied = agent.request(
        "stripe",
        "refund",
        json!({"charge": "ch_beta", "amount": 2000}),
    );
    assert_eq!(denied["decision"], "deny", "{denied}");
    assert!(denied["grant_id"].is_null(), "{denied}");

    // 2. Init creates an inert document through parsed production authority dispatch.
    let initialized = authority(
        &daemon,
        repo.path(),
        presence.clone(),
        &["doc", "check", "--init"],
    );
    assert_eq!(initialized.exit_code, 0, "{}", initialized.text);
    let initialized_bytes = std::fs::read(&document_path).unwrap();
    let initialized_document =
        cermet_cli::cermet_document::ManagedDocument::parse(&initialized_bytes).unwrap();
    assert_eq!(initialized_document.body(), "");
    assert!(initialized_document.marker().is_none());

    // 3. A real vendored Stripe bound is accepted, then Stripe denies outside its envelope and its
    // exact hint is fed back.
    let stripe_seed = "allow stripe.refund where charge = \"ch_alpha\" and amount <= 5000";
    let stripe_added = authority(
        &daemon,
        repo.path(),
        presence.clone(),
        &["rules", "allow", stripe_seed, "--yes"],
    );
    assert_eq!(stripe_added.exit_code, 0, "{}", stripe_added.text);
    let denied_stripe = agent.request(
        "stripe",
        "refund",
        json!({"charge": "ch_beta", "amount": 2000}),
    );
    assert_eq!(denied_stripe["decision"], "deny", "{denied_stripe}");
    let stripe_hint_rule = hint_rule(&denied_stripe);
    let widened_stripe = authority(
        &daemon,
        repo.path(),
        presence.clone(),
        &["rules", "allow", &stripe_hint_rule, "--yes"],
    );
    assert_eq!(widened_stripe.exit_code, 0, "{}", widened_stripe.text);
    assert!(
        widened_stripe
            .text
            .contains(&canonical_allow(&stripe_hint_rule)),
        "{}",
        widened_stripe.text
    );

    assert_eq!(presence.count(), 2);

    // 4. Incremental authority is unexported and init's bytes are untouched.
    let unexported = authority(&daemon, repo.path(), presence.clone(), &["doc", "status"]);
    assert_eq!(unexported.exit_code, 1, "{}", unexported.text);
    assert!(unexported.text.contains("state: unexported_live"));
    assert_eq!(std::fs::read(&document_path).unwrap(), initialized_bytes);

    // 5. Export is non-authorizing and emits one complete canonical document.
    let before_export_presence = presence.count();
    let exported = authority(&daemon, repo.path(), presence.clone(), &["doc", "export"]);
    assert_eq!(exported.exit_code, 0, "{}", exported.text);
    assert!(exported.text.contains("state: aligned"));
    assert_eq!(presence.count(), before_export_presence);
    let exported_bytes = std::fs::read(&document_path).unwrap();
    let exported_document =
        cermet_cli::cermet_document::ManagedDocument::parse(&exported_bytes).unwrap();
    assert!(
        cermet_cli::cermet_document::analyze_body(exported_document.body())
            .unwrap()
            .is_canonical
    );
    assert_eq!(exported_document.body().lines().count(), 2);

    // 6. Restart uses the daemon's production adoption/recovery function over the same durable state.
    drop(agent);
    daemon.stop();
    let daemon = start_daemon(&runtime, state.path(), 2);
    let mut agent = AgentSession::connect(&daemon.agent_socket);
    let restarted = authority(&daemon, repo.path(), presence.clone(), &["doc", "status"]);
    assert_eq!(restarted.exit_code, 0, "{}", restarted.text);
    assert!(restarted.text.contains("state: aligned"));

    // 7. The credentialed vendored execution succeeds; the disabled local request is a definite
    // persisted denial and cannot produce an executable handle.
    let stripe_request_id = request_id(&agent.request(
        "stripe",
        "refund",
        json!({"charge": "ch_beta", "amount": 2000}),
    ));
    let stripe_execution = agent.execute(&stripe_request_id);
    assert_eq!(stripe_execution["kind"], "executed", "{stripe_execution}");
    assert_eq!(stripe_execution["ok"], true, "{stripe_execution}");
    assert_eq!(stripe_execution["provider"], "stripe");
    assert_eq!(
        stripe_execution["result"],
        json!({"id": "[SECRET_REDACTED]", "charge": "ch_beta", "amount": 2000, "status": "succeeded"})
    );
    assert_redacted(&stripe_execution, "agent execute response");

    let stripe_requests = runtime.block_on(stripe.received_requests()).unwrap();
    assert_eq!(stripe_requests.len(), 1, "one grant must produce one call");
    let stripe_request = &stripe_requests[0];
    assert_eq!(stripe_request.method.as_str(), "POST");
    assert_eq!(stripe_request.url.path(), "/v1/refunds");
    assert_eq!(stripe_request.url.query(), None);
    assert_eq!(
        stripe_request
            .headers
            .get("authorization")
            .unwrap()
            .to_str()
            .unwrap(),
        format!("Bearer {FAKE_STRIPE_TOKEN}")
    );
    assert_eq!(
        stripe_request
            .headers
            .get("content-type")
            .unwrap()
            .to_str()
            .unwrap(),
        "application/x-www-form-urlencoded"
    );
    let mut stripe_form: Vec<(String, String)> =
        serde_urlencoded::from_bytes(&stripe_request.body).unwrap();
    stripe_form.sort();
    assert_eq!(
        stripe_form,
        vec![
            ("amount".to_string(), "2000".to_string()),
            ("charge".to_string(), "ch_beta".to_string()),
        ],
        "only the approved frozen fields may reach Stripe"
    );

    let artifact_handle = stripe_execution["artifact"]
        .as_str()
        .expect("a retained Stripe response has an agent-readable artifact");
    let artifact = agent.artifact(artifact_handle);
    assert_eq!(artifact["kind"], "artifact", "{artifact}");
    assert_redacted(&artifact, "agent artifact frame");

    let audit_verified = agent.verify_audit();
    assert_eq!(audit_verified["kind"], "audit_verified", "{audit_verified}");
    assert_eq!(audit_verified["ok"], true, "{audit_verified}");
    let status = agent.status(&stripe_request_id);
    assert_eq!(status["kind"], "status", "{status}");
    assert_eq!(status["phase"], "terminal", "{status}");
    assert_eq!(status["outcome"], "succeeded", "{status}");
    assert_eq!(status["terminal_receipt"], stripe_execution);
    assert_redacted(
        &status["terminal_receipt"],
        "authenticated terminal audit receipt",
    );

    // 8. A body edit is unapplied and cannot narrow the served Stripe authority.
    let stripe_narrow = "allow stripe.refund where charge = \"ch_alpha\" and amount <= 1000";
    let stripe_beta = "allow stripe.refund where charge = \"ch_beta\" and amount <= 5000";
    let draft = format!("{stripe_narrow}\n{stripe_beta}\n");
    rewrite_body(&document_path, &draft);
    let unapplied = authority(&daemon, repo.path(), presence.clone(), &["doc", "status"]);
    assert_eq!(unapplied.exit_code, 1, "{}", unapplied.text);
    assert!(unapplied.text.contains("state: unapplied_document"));
    assert_eq!(
        agent.request(
            "stripe",
            "refund",
            json!({"charge": "ch_alpha", "amount": 2000}),
        )["decision"],
        "allow"
    );

    // 9. Check/fix/diff are inert; apply alone performs one whole-document presence ceremony.
    let before_apply_presence = presence.count();
    rewrite_body(&document_path, &draft.replacen("allow ", " allow   ", 1));
    let checked = authority(&daemon, repo.path(), presence.clone(), &["doc", "check"]);
    assert_eq!(checked.exit_code, 1, "{}", checked.text);
    assert!(checked.text.contains("canonical: no"));
    let fixed = authority(
        &daemon,
        repo.path(),
        presence.clone(),
        &["doc", "check", "--fix"],
    );
    assert_eq!(fixed.exit_code, 0, "{}", fixed.text);
    let diffed = authority(&daemon, repo.path(), presence.clone(), &["doc", "diff"]);
    assert_eq!(diffed.exit_code, 1, "{}", diffed.text);
    assert!(diffed.text.contains("state: unapplied_document"));
    assert_eq!(presence.count(), before_apply_presence);
    let applied = authority(&daemon, repo.path(), presence.clone(), &["doc", "apply"]);
    assert_eq!(applied.exit_code, 0, "{}", applied.text);
    assert!(applied.text.contains("state: aligned"));
    assert_eq!(presence.count(), before_apply_presence + 1);
    assert_eq!(
        agent.request(
            "stripe",
            "refund",
            json!({"charge": "ch_alpha", "amount": 2000}),
        )["decision"],
        "deny"
    );

    // 10. A direct revoke is unexported; export returns to aligned without presence.
    let pre_revoke_document = std::fs::read(&document_path).unwrap();
    let revoked = authority(
        &daemon,
        repo.path(),
        presence.clone(),
        &["rules", "revoke", "1", "--yes"],
    );
    assert_eq!(revoked.exit_code, 0, "{}", revoked.text);
    assert!(revoked.text.contains("document_sync: unexported_live"));
    let after_revoke_presence = presence.count();
    let reexported = authority(&daemon, repo.path(), presence.clone(), &["doc", "export"]);
    assert_eq!(reexported.exit_code, 0, "{}", reexported.text);
    assert!(reexported.text.contains("state: aligned"));
    assert_eq!(presence.count(), after_revoke_presence);

    // 11. A stale checkout reports direction, then divergence requires explicit replacement.
    let stale = tempfile::tempdir().unwrap();
    std::fs::create_dir(stale.path().join(".git")).unwrap();
    std::fs::write(stale.path().join("CERMET.md"), pre_revoke_document).unwrap();
    let stale_status = authority(&daemon, stale.path(), presence.clone(), &["doc", "status"]);
    assert_eq!(stale_status.exit_code, 1, "{}", stale_status.text);
    assert!(stale_status.text.contains("state: unexported_live"));
    let divergent = format!(
        "allow stripe.refund where charge = \"ch_gamma\" and amount <= 5000\n{stripe_beta}\n"
    );
    rewrite_body(&stale.path().join("CERMET.md"), &divergent);
    let diverged = authority(&daemon, stale.path(), presence.clone(), &["doc", "status"]);
    assert_eq!(diverged.exit_code, 1, "{}", diverged.text);
    assert!(diverged.text.contains("state: diverged"));
    let refused = authority(&daemon, stale.path(), presence.clone(), &["doc", "apply"]);
    assert_eq!(refused.exit_code, 1, "{}", refused.text);
    assert!(refused.text.contains("rerun with --replace-live"));
    assert_eq!(presence.count(), after_revoke_presence);

    // 12. The real owner framed/audited transition catches an already-minted Stripe grant before I/O.
    let blocked_request_id = request_id(&agent.request(
        "stripe",
        "refund",
        json!({"charge": "ch_beta", "amount": 2000}),
    ));
    let requests_before_lockdown = runtime.block_on(stripe.received_requests()).unwrap().len();
    let occurrence = owner_lockdown(&daemon);
    assert_eq!(occurrence.len(), 64);
    // The owner handler returns Transitioned only after BrokerAuditSink records this occurrence.
    let blocked = agent.execute(&blocked_request_id);
    assert_eq!(blocked["kind"], "error", "{blocked}");
    assert_eq!(
        runtime.block_on(stripe.received_requests()).unwrap().len(),
        requests_before_lockdown,
        "owner lockdown must stop the grant before the provider I/O adapter"
    );
    assert_eq!(
        presence.count(),
        4,
        "one seed bound + one emitted hint + one apply + one revoke"
    );

    assert_eq!(
        runtime.block_on(stripe.received_requests()).unwrap().len(),
        1,
        "exactly one provider call crossed the Stripe boundary"
    );
    drop(agent);
    daemon.stop();
    std::env::remove_var("CERMET_STRIPE_BASE_URL");
}
