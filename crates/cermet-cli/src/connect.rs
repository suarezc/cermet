//! `cermet connect <provider>` — reuse an existing connection or a token the user already has,
//! and store it in the vault.
//!
//! Secret hygiene (the invariant): the raw provider token is a [`SecretString`] from the moment it is
//! discovered or captured until it is handed to the daemon's `connect` (which vaults it and replies a
//! secret-free `ConnectOutcome`). It is NEVER printed, echoed, logged, or placed in an error/`Debug` —
//! discovery only ever surfaces the ENV-VAR NAME (`$VERCEL_TOKEN`) or the source label (`gh auth
//! token`), never the value, and the capture path suppresses terminal echo (see [`crate::tty`]).

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

use cermet_ctl_client::broker_client::CtlBrokerClient;

use crate::tty::Terminal;
use crate::{CliError, CliOutput};

/// The parsed `connect` arguments.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectArgs {
    pub provider: String,
    pub account_label: Option<String>,
    pub replace: bool,
    pub adopt: bool,
}

/// Where a provider token may already live: env vars (walked in `token_env_names` order) and, for
/// GitHub, a `gh auth login` session. Behind a trait so discovery is deterministic in tests.
pub trait TokenSource {
    /// The value of env var `name`, wrapped as a secret; `None` when unset/empty.
    fn env(&self, name: &str) -> Option<SecretString>;
    /// The token from a `gh auth token` session, if the `gh` CLI has one.
    fn gh_token(&self) -> Option<SecretString>;
}

/// The real token source: the process environment + the `gh` CLI.
pub struct StdTokenSource;

impl TokenSource for StdTokenSource {
    fn env(&self, name: &str) -> Option<SecretString> {
        match std::env::var(name) {
            Ok(v) if !v.trim().is_empty() => Some(SecretString::new(v)),
            _ => None,
        }
    }
    fn gh_token(&self) -> Option<SecretString> {
        let out = std::process::Command::new("gh")
            .args(["auth", "token"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        let tok = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if tok.is_empty() {
            None
        } else {
            Some(SecretString::new(tok))
        }
    }
}

/// The provider's token-creation page, offered interactively when nothing is discovered.
fn token_page(provider: &str) -> Option<&'static str> {
    match provider {
        "vercel" => Some("https://vercel.com/account/tokens"),
        "github" => Some("https://github.com/settings/tokens"),
        _ => None,
    }
}

/// Look for a token the user already has, so they needn't paste a new one. Walks the
/// `token_env_names` list IN ORDER (canonical name first), then the `gh` CLI for GitHub. Returns the
/// token PLUS a human-readable SOURCE label (the var name or `gh auth token`) — never the value.
pub fn discover_token(provider: &str, src: &dyn TokenSource) -> Option<(SecretString, String)> {
    for var in cermet_broker_core::provider_tokens::token_env_names(provider) {
        if let Some(val) = src.env(&var) {
            let trimmed = val.expose_secret().trim().to_string();
            if !trimmed.is_empty() {
                return Some((SecretString::new(trimmed), format!("${var}")));
            }
        }
    }
    if provider == "github" {
        if let Some(tok) = src.gh_token() {
            if !tok.expose_secret().trim().is_empty() {
                return Some((tok, "gh auth token".to_string()));
            }
        }
    }
    None
}

/// The secret-free connect outcome the daemon replies. Deserialized LOCALLY (not into
/// `cermet_lang::ConnectOutcome`); required fields absent make it malformed and fail closed.
#[derive(Debug, Deserialize)]
struct ConnectView {
    stored: bool,
    account_label: Option<String>,
    reference: String,
    replaced: bool,
}

/// One stored-credential row (a subset of `cermet_lang::SafeCredential`), for the existing-connection
/// check.
#[derive(Debug, Deserialize)]
struct CredentialRow {
    provider: String,
    reference: String,
    created_at: String,
}

fn parse_connect_view(reply: &str) -> Result<ConnectView, CliError> {
    serde_json::from_str(reply)
        .map_err(|e| CliError::Malformed(format!("malformed connect outcome: {e}")))
}

/// Drive `cermet connect`. See the module doc for the secret-custody guarantee.
pub async fn run_connect(
    client: &CtlBrokerClient,
    term: &dyn Terminal,
    src: &dyn TokenSource,
    args: &ConnectArgs,
    cwd: &std::path::Path,
) -> Result<CliOutput, CliError> {
    let interactive = term.is_interactive();
    let provider = &args.provider;

    // Existing-connection reuse.
    let creds_reply = client.list_credentials().await.map_err(CliError::Server)?;
    let creds: Vec<CredentialRow> = serde_json::from_str(&creds_reply)
        .map_err(|e| CliError::Malformed(format!("malformed credentials view: {e}")))?;
    if let Some(existing) = creds.iter().find(|c| &c.provider == provider) {
        if !args.replace {
            let added: String = existing.created_at.chars().take(10).collect();
            let where_ = format!("{}, added {added}", existing.reference);
            // The credential existing says nothing about THIS repository: short-circuiting here left
            // an agent in a new repo with no reachable path to the wiring, so
            // an unwired cwd repo gets the SAME offer a first-time connect prints. An already-wired
            // repo (or no repo at all) adds nothing.
            let offer = |term: &dyn Terminal| {
                if provider == "github" && !repo_is_wired(cwd) {
                    wire_github_repo(term, cwd)
                } else {
                    String::new()
                }
            };
            if interactive {
                if !term.confirm(
                    &format!("{provider} is already connected ({where_}). Replace it?"),
                    false,
                ) {
                    return Ok(CliOutput {
                        text: format!("Keeping the existing connection.{}", offer(term)),
                        ok: true,
                    });
                }
            } else {
                return Ok(CliOutput {
                    text: format!(
                        "{provider} is already connected ({where_}). Use --replace to overwrite.{}",
                        offer(term)
                    ),
                    ok: true,
                });
            }
        }
    }

    // Discover-or-capture the token (SecretString the whole way).
    let mut token: Option<SecretString> = None;
    let mut source: Option<String> = None;
    if let Some((discovered, discovered_src)) = discover_token(provider, src) {
        if args.adopt
            || (interactive
                && term.confirm(
                    &format!("Found a {provider} token via {discovered_src}. Use it?"),
                    true,
                ))
        {
            token = Some(discovered);
            source = Some(discovered_src);
        }
    }
    if token.is_none() {
        if interactive {
            if let Some(page) = token_page(provider) {
                if term.confirm(&format!("Open {page} to create a {provider} token?"), true) {
                    term.launch(page);
                    // (an instruction to the human; the token is captured next, never echoed)
                }
            }
        }
        // Fail closed: a refused echo-suppressed prompt propagates — the token is never
        // captured on a terminal where it could echo.
        let captured = term.read_secret(&format!("{provider} token"))?;
        if !captured.expose_secret().trim().is_empty() {
            token = Some(SecretString::new(
                captured.expose_secret().trim().to_string(),
            ));
        }
    }
    let token = match token {
        Some(t) => t,
        None => {
            return Err(CliError::Refused(
                "No token provided — nothing connected.".to_string(),
            ));
        }
    };

    // The label is echoed in the receipt and the agent-facing credential view — the
    // one place a pasted-token-as-label accident would leak plaintext. Both values are in hand
    // exactly here, so refuse the collision at the boundary.
    if let Some(label) = &args.account_label {
        if label.contains(token.expose_secret()) {
            return Err(CliError::Refused(
                "The label contains the token itself — labels are printed in receipts and \
                 visible to agents. Nothing connected."
                    .to_string(),
            ));
        }
    }

    // Store only. The raw token crosses to the daemon here and nowhere else.
    let reply = client
        .connect(provider.clone(), token, args.account_label.clone())
        .await
        .map_err(CliError::Server)?;
    let out = parse_connect_view(&reply)?;
    // `stored` is the daemon REPORTING its own outcome. There is deliberately no companion check
    // that the daemon echoed back the provider name the client had just sent it, one turn earlier,
    // on the same socket.
    if !out.stored {
        return Err(CliError::Malformed(
            "daemon returned an invalid storage receipt".to_string(),
        ));
    }

    // Success — secret-free reporting.
    let label = out.account_label.as_deref().unwrap_or("(none)");
    let replaced = if out.replaced { "yes" } else { "no" };
    let mut text = format!(
        "✓ {provider} credential stored — {}\n  Label: {label}; replaced: {replaced}.\n  Your token is in Cermet's vault. The agent never sees it.",
        out.reference
    );
    if let Some(s) = source {
        text.push_str(&format!(
            "\n  Note: {s} still holds this token — Cermet hasn't taken sole custody of it yet."
        ));
    }
    if provider == "github" {
        text.push_str(&wire_github_repo(term, cwd));
    }
    Ok(CliOutput { text, ok: true })
}

/// Does the repository at `cwd` already reach github through the broker? `false` outside a
/// repository — there is nothing there to be wired.
fn repo_is_wired(cwd: &std::path::Path) -> bool {
    use crate::git_remote::wiring;

    wiring::remotes(cwd).is_some_and(|remotes| {
        remotes.iter().any(wiring::Remote::is_brokered) || wiring::insteadof_configured(cwd)
    })
}

/// The one-time git wiring `connect github` offers: point this repository's github remote at the
/// broker, so that PLAIN `git push` goes through it.
///
/// The shape is a per-repo `cermet::github/<owner>/<repo>` remote URL — git's own transport-helper
/// addressing, visible in `git remote -v`, set with git's own `remote set-url`. Cermet writes no
/// config format of its own and offers no `cermet git` wrapper: git talks to git, and the broker's
/// part in the flow is the credentialed hop the helper reaches.
///
/// Never silent: a non-interactive run (or a declined prompt) prints the exact command instead of
/// editing the repository behind the operator's back.
fn wire_github_repo(term: &dyn Terminal, cwd: &std::path::Path) -> String {
    use crate::git_remote::wiring;

    let Some(remotes) = wiring::remotes(cwd) else {
        return String::new();
    };
    if repo_is_wired(cwd) {
        return "\n  This repository already reaches github through Cermet — \
                verify anytime: cermet check github"
            .to_string();
    }
    let Some((remote, brokered_url)) = remotes.iter().find_map(|r| Some((r, r.brokered_url()?)))
    else {
        return String::new();
    };
    let command = format!("git remote set-url {} {brokered_url}", remote.name);
    if term.is_interactive()
        && term.confirm(
            &format!(
                "Route this repository's `{}` through Cermet? ({command})",
                remote.name
            ),
            true,
        )
    {
        return match wiring::set_url(cwd, &remote.name, &brokered_url) {
            Ok(()) => format!(
                "\n  Wired: {} → {brokered_url}. Plain `git push` now goes through Cermet.\
                 \n  Verify anytime: cermet check github",
                remote.name
            ),
            Err(error) => format!(
                "\n  Could not wire `{}` ({error}). Run it yourself:\n      {command}\
                 \n  Verify anytime: cermet check github",
                remote.name
            ),
        };
    }
    format!(
        "\n  This repository still pushes straight to github. To route it through Cermet:\
         \n      {command}\
         \n  Verify anytime: cermet check github"
    )
}

/// A public test double: a fixed env map + optional `gh` token. Fake values only — a test never puts a
/// real token here.
pub struct MapTokenSource {
    pub env: std::collections::HashMap<String, String>,
    pub gh: Option<String>,
}

impl TokenSource for MapTokenSource {
    fn env(&self, name: &str) -> Option<SecretString> {
        self.env
            .get(name)
            .filter(|v| !v.trim().is_empty())
            .map(|v| SecretString::new(v.clone()))
    }
    fn gh_token(&self) -> Option<SecretString> {
        self.gh.clone().map(SecretString::new)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn src(env: &[(&str, &str)], gh: Option<&str>) -> MapTokenSource {
        MapTokenSource {
            env: env
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            gh: gh.map(str::to_string),
        }
    }

    #[test]
    fn discover_prefers_the_canonical_env_var_first() {
        // token_env_names("vercel") is canonical-first (VERCEL_TOKEN, VERCEL_API_TOKEN, …).
        let s = src(
            &[
                ("VERCEL_API_TOKEN", "second"),
                ("VERCEL_TOKEN", "canonical"),
            ],
            None,
        );
        let (tok, label) = discover_token("vercel", &s).expect("a token is discovered");
        assert_eq!(tok.expose_secret(), "canonical");
        assert_eq!(label, "$VERCEL_TOKEN");
    }

    #[test]
    fn discover_falls_back_to_a_later_alias_then_gh() {
        let s = src(&[("VERCEL_ACCESS_TOKEN", "aliased")], None);
        let (tok, label) = discover_token("vercel", &s).expect("aliased token");
        assert_eq!(tok.expose_secret(), "aliased");
        assert_eq!(label, "$VERCEL_ACCESS_TOKEN");

        // GitHub with no env var falls through to `gh auth token`.
        let g = src(&[], Some("ghp_from_cli_FAKE"));
        let (tok, label) = discover_token("github", &g).expect("gh token");
        assert_eq!(tok.expose_secret(), "ghp_from_cli_FAKE");
        assert_eq!(label, "gh auth token");
    }

    #[test]
    fn discover_returns_none_when_nothing_is_present() {
        assert!(discover_token("vercel", &src(&[], None)).is_none());
        // A whitespace-only env value is treated as absent.
        assert!(discover_token("vercel", &src(&[("VERCEL_TOKEN", "   ")], None)).is_none());
    }

    #[test]
    fn a_discovered_secret_is_redacted_in_debug() {
        let s = src(&[("VERCEL_TOKEN", "supersecret_FAKE")], None);
        let (tok, _) = discover_token("vercel", &s).unwrap();
        assert!(
            !format!("{tok:?}").contains("supersecret_FAKE"),
            "SecretString Debug must not leak the token"
        );
    }

    #[test]
    fn a_malformed_connect_view_fails_closed() {
        assert!(matches!(
            parse_connect_view("{ not json"),
            Err(CliError::Malformed(_))
        ));
        // Missing the required storage-receipt fields is malformed, never a silent success.
        assert!(matches!(
            parse_connect_view(r#"{"provider":"vercel"}"#),
            Err(CliError::Malformed(_))
        ));
    }
}
