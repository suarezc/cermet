//! Real-path test harness for the operator CLI: a spun-up dev-mode cermetd broker behind a
//! `ctl.sock`, plus the keyless [`CtlBrokerClient`] the CLI drives (the REAL ctl path, never an
//! in-process double).
//!
//! ⚠️  THIS DOUBLE DELIBERATELY BYPASSES THE CTL-AUTH BOUNDARY. ⚠️
//! It serves via `handle_ctl_connection(.., FIXTURE_DAEMON_UID, ..)` — a FAKE daemon uid distinct
//! from the test's real `getuid()` — so `ctl_authorized(getuid, getuid, FIXTURE_DAEMON_UID)`
//! AUTHORIZES every call. PRODUCTION does NOT (it derives the daemon uid from the process, so
//! same-uid collapses to deny). The injected uid is a HANDLER-WIRING convenience only; the ctl-auth
//! boundary's real verdict is proven in the daemon's own ctl-boundary suites, never here.

#![allow(dead_code)]

use cermet_broker_actor::{spawn, spawn_with_sentence_authority};
use cermet_core::{AuthenticatedSentenceAuthority, BrokerConfig, SentenceAuthoritySource};
use cermet_ctl_client::broker_client::CtlBrokerClient;
use cermet_daemon::ctl::{bind_ctl_socket, handle_ctl_connection};
use cermet_daemon::serve::ServeTimeouts;
use tempfile::TempDir;

/// A synthetic daemon uid, distinct from the test's real peer uid, so the ctl gate's `peer != daemon`
/// half holds and the approver (`= getuid()`) is authorized. See the module doc: BOUNDARY-BYPASS.
const FIXTURE_DAEMON_UID: u32 = 999_001;
/// A synthetic agent-service uid, distinct from both the daemon's and the test's own, so the
/// git-plane admission set the doctor reports ({agent_uid, approver_uid}) is the service-mode shape.
const FIXTURE_AGENT_UID: u32 = 999_002;

struct ClearLockdown;

impl cermet_core::LockdownSource for ClearLockdown {
    fn is_engaged(&self) -> bool {
        false
    }
}

/// mock-vercel is the OFFLINE provider (no network), so an approved deploy actually executes.
pub const TEST_POLICY: &str = "providers:\n  mock-vercel:\n    ask:\n      - action: deploy\n";

/// A running dev-mode cermetd broker behind a `ctl.sock`, plus the keyless client the CLI uses.
pub struct BrokerFixture {
    pub client: CtlBrokerClient,
    sock_path: std::path::PathBuf,
    /// A second handle to the SAME broker, so a test can also stand up the AGENT plane against it
    /// (proving both planes serve the one catalog join needs both sockets, one broker).
    broker: cermet_broker_actor::BrokerHandle,
    _home: TempDir,
}

impl BrokerFixture {
    /// Spawn a broker with `policy_yaml` over a fresh `ctl.sock`. Must be called from within a tokio
    /// runtime (the daemon dispatch blocks on the broker actor via the captured runtime handle).
    pub fn new(policy_yaml: &str) -> Self {
        Self::with_record_admin(policy_yaml, None)
    }

    pub fn with_record_admin(
        _policy_yaml: &str,
        record_admin: Option<
            std::sync::Arc<dyn cermet_daemon::sentence_record::SentenceRecordAdmin>,
        >,
    ) -> Self {
        let home = Self::hardened_home();
        let broker = spawn(Self::config(home.path())).expect("broker opens");
        Self::serve(home, broker, record_admin)
    }

    /// The home IS the runtime dir the keyless client's dir-contract inspects; harden it to
    /// 0o700 to mirror a real daemon-hardened runtime dir (tempdir honors the umask → 0o755).
    fn hardened_home() -> TempDir {
        let home = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(
            home.path(),
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .expect("harden temp home");
        home
    }

    fn config(home_path: &std::path::Path) -> BrokerConfig {
        BrokerConfig {
            git: cermet_core::git::GitConfig::at(
                std::env::temp_dir().join("cermet-test-quarantine"),
            ),
            dir: home_path.to_path_buf(),
            master_key: vec![5u8; 32],
            action_templates: cermet_core::templates::VENDORED_CATALOG
                .iter()
                .map(|s| s.to_string())
                .collect(),
            provider_descriptors: BrokerConfig::vendored_descriptors(),
            artifacts: cermet_core::ArtifactConfig::default(),
        }
    }

    fn serve(
        home: TempDir,
        broker: cermet_broker_actor::BrokerHandle,
        record_admin: Option<
            std::sync::Arc<dyn cermet_daemon::sentence_record::SentenceRecordAdmin>,
        >,
    ) -> Self {
        let home_path = home.path().to_path_buf();
        let agent_plane_broker = broker.clone();
        let (listener, sock_path) = bind_ctl_socket(&home_path).expect("bind ctl.sock");
        let approver_uid = nix::unistd::getuid().as_raw();
        let rt = tokio::runtime::Handle::current();
        let serve_home = home_path.clone();
        // The unified sentence record admin over a fresh state dir (default: an empty, deny-all record).
        let record_admin: std::sync::Arc<dyn cermet_daemon::sentence_record::SentenceRecordAdmin> =
            record_admin.unwrap_or_else(|| {
                cermet_daemon::sentence_record::build_record_store(&home_path, None)
            });

        std::thread::spawn(move || {
            // connect-per-call → one accept per client call; the handler loops until EOF.
            while let Ok((conn, _)) = listener.accept() {
                handle_ctl_connection(
                    conn,
                    &broker,
                    &rt,
                    approver_uid,
                    // The ctl Doctor request consumes these — the git-plane row reports
                    // whether the caller is in {agent_uid, approver_uid}. A distinct fake
                    // agent uid keeps that set realistic (the approver — this test's uid — is
                    // admitted; a stranger is not).
                    FIXTURE_AGENT_UID,
                    FIXTURE_DAEMON_UID, // BOUNDARY-BYPASS (see module doc).
                    &serve_home,
                    &serve_home,
                    &serve_home,
                    ServeTimeouts::default(),
                    None,
                    None,
                    // service_mode: the git-plane admission set the doctor reports is then the real
                    // {agent_uid, approver_uid} shape rather than dev's {daemon_uid}.
                    true,
                    // CUSTODY-LADDER: the fixture declares the rung a Linux box lands on.
                    Some(cermet_ipc::custody::CustodyProfile::SystemdHost),
                    false,
                    &record_admin,
                    &(std::sync::Arc::new(ClearLockdown)
                        as std::sync::Arc<dyn cermet_core::LockdownSource>),
                );
            }
        });

        Self {
            // The fixture serves from the test's own uid (it IS the keyholder here), and binds
            // ctl.sock in the 0700 temp home, so expected_daemon_uid = getuid() + the dir-contract hold.
            client: CtlBrokerClient::new(sock_path.clone(), nix::unistd::getuid().as_raw()),
            sock_path,
            broker: agent_plane_broker,
            _home: home,
        }
    }

    /// A fixture whose broker serves EXACTLY `rules_text` as its live sentence authority (the empty
    /// string is the deny-all corpus). Mirrors the agent-socket fixture: a fixed authority source is
    /// the shortest honest way to put a rule in force, and it exercises the same decision kernel the
    /// staged custody path installs into.
    pub fn with_sentence_rules(rules_text: &str) -> Self {
        struct FixedSentenceAuthority(cermet_core::sentence::RuleSet);

        impl SentenceAuthoritySource for FixedSentenceAuthority {
            fn current_authority(&self) -> cermet_core::Result<AuthenticatedSentenceAuthority> {
                Ok(AuthenticatedSentenceAuthority {
                    digest: cermet_core::sentence::authority_digest(&self.0),
                    rules: self.0.clone(),
                })
            }
        }

        let home = Self::hardened_home();
        let home_path = home.path().to_path_buf();
        let rules = cermet_core::sentence::parse_rules(rules_text).expect("fixture rules parse");
        let broker = spawn_with_sentence_authority(
            Self::config(&home_path),
            std::sync::Arc::new(FixedSentenceAuthority(rules)),
        )
        .expect("broker opens");
        Self::serve(home, broker, None)
    }

    /// Vault an obviously-fake credential so an offline (`mock-*`) verb can actually execute.
    pub async fn connect_mock_credential(
        &self,
        provider: &str,
    ) -> Result<String, cermet_lang::Error> {
        self.client
            .connect(
                provider.to_string(),
                secrecy::SecretString::new("mock-token".to_string()),
                None,
            )
            .await
    }

    pub fn sock_path(&self) -> &std::path::Path {
        &self.sock_path
    }

    /// Bind `agent.sock` beside this fixture's `ctl.sock` and serve EXACTLY ONE connection from the
    /// SAME broker, returning the socket path. The agent plane admits only the operator uid, which
    /// in-test is our own. Call once per agent-side round trip (re-binding in the same dir works
    /// once the prior listener has dropped).
    pub fn serve_agent_once(&self) -> std::path::PathBuf {
        let runtime_dir = self.sock_path.parent().expect("ctl.sock has a parent");
        let (listener, path) =
            cermet_daemon::serve::bind_agent_socket(runtime_dir).expect("bind agent.sock");
        let broker = self.broker.clone();
        let rt = tokio::runtime::Handle::current();
        std::thread::spawn(move || {
            let (conn, _addr) = listener.accept().expect("accept");
            cermet_daemon::serve::handle_connection(
                conn,
                &broker,
                &rt,
                "cermet-catalog-parity-test",
                Some(nix::unistd::getuid().as_raw()),
                ServeTimeouts::default(),
            );
        });
        path
    }
}

/// The one shipped `cermet` executable, for the tests that drive the REAL binary.
///
/// ONE-BINARY: cargo's `CARGO_BIN_EXE_<name>` exists only for a package's OWN bin targets, and the
/// sole bin now lives in the composition crate `cermet-bin`. Every workspace test command
/// (`cargo test --workspace`, `cargo nextest run --workspace`) builds that target before running
/// anything, and it lands beside this test binary's own profile directory — so locate it there and
/// say plainly what to run if it is absent, rather than guessing at a path.
pub fn cermet_binary() -> std::path::PathBuf {
    let test_exe = std::env::current_exe().expect("a test binary knows its own path");
    let profile_dir = test_exe
        .parent()
        .and_then(|deps| deps.parent())
        .expect("the test binary lives in target/<profile>/deps");
    let binary = profile_dir.join("cermet");
    assert!(
        binary.is_file(),
        "the one shipped `cermet` binary is not built at {}; run the WORKSPACE suite \
         (`cargo nextest run --workspace`), or `cargo build -p cermet-bin` first",
        binary.display()
    );
    binary
}

/// A [`Command`](std::process::Command) for that binary with its operator-local state ISOLATED.
///
/// Every operator-CLI invocation appends to the output journal under `$XDG_STATE_HOME`. A test that
/// spawned the binary with the developer's own environment would write into THEIR journal, so every
/// spawn points that variable at a directory inside the build tree — swept by `cargo clean` like any
/// other build output, and never the machine's own state directory. Tests that assert ON the
/// journal set the variable themselves and do not use this.
pub fn cermet_command() -> std::process::Command {
    let binary = cermet_binary();
    let state = binary
        .parent()
        .expect("the binary lives in target/<profile>")
        .join("cermet-test-state");
    let mut command = std::process::Command::new(binary);
    command.env("XDG_STATE_HOME", state);
    command
}
