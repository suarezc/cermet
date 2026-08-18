//! The single Rust owner for provider token env-var NAMES.
//!
//! This is the one authoritative table of the environment-variable names under which a
//! provider's access token may hide on disk or in the live env. It replaces the two duplicated
//! Python tables — `PROVIDER_TOKEN_ENV_NAMES` (secure.py) and `_TOKEN_ENV` (cli.py). The list is
//! ordered **canonical-name-first**, so it serves both consumers with one source:
//!   * `secure` scrubs the WHOLE list (every alias a loose copy might use);
//!   * `connect` discovery (a later milestone) walks the list IN ORDER, preferring the canonical
//!     name.
//!
//! Keyless by construction: this only names env vars, it never reads or holds a token value.

/// The env-var names to scrub / discover for a provider, canonical name first.
///
/// An unknown provider falls back to `<PROVIDER>_TOKEN` — never an empty list, so a caller can
/// always fail closed on a real (if guessed) name.
pub fn token_env_names(provider: &str) -> Vec<String> {
    let fixed: &[&str] = match provider {
        "vercel" => &[
            "VERCEL_TOKEN",
            "VERCEL_API_TOKEN",
            "VERCEL_ACCESS_TOKEN",
            "NOW_TOKEN",
        ],
        "github" => &[
            "GITHUB_TOKEN",
            "GH_TOKEN",
            "GITHUB_PAT",
            "GITHUB_ACCESS_TOKEN",
        ],
        other => return vec![format!("{}_TOKEN", other.to_uppercase())],
    };
    fixed.iter().map(|s| s.to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_provider_and_fallback() {
        assert!(token_env_names("vercel").contains(&"VERCEL_TOKEN".to_string()));
        assert!(token_env_names("github").contains(&"GH_TOKEN".to_string()));
        // unknown provider gets a sensible default slot, never empty
        assert_eq!(token_env_names("fly"), vec!["FLY_TOKEN".to_string()]);
    }

    #[test]
    fn canonical_name_is_first() {
        assert_eq!(token_env_names("vercel")[0], "VERCEL_TOKEN");
        assert_eq!(token_env_names("github")[0], "GITHUB_TOKEN");
    }
}
