//! Vendored sentence-set catalog.

use std::collections::{BTreeMap, HashSet};
use std::sync::OnceLock;

use serde::Deserialize;
use sha2::{Digest, Sha256};

const VENDORED_SETS: &str = include_str!("../sets.yaml");

/// One immutable, content-addressed expansion of a provider set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetSnapshot {
    provider: String,
    name: String,
    digest: String,
    members: Vec<String>,
}

impl SetSnapshot {
    /// Build the canonical expansion: identifiers are validated, members are sorted and deduplicated,
    /// and the digest commits to the provider, set name, and every expanded member.
    pub fn new(provider: &str, name: &str, mut members: Vec<String>) -> Option<Self> {
        if !valid_ident(provider) || !valid_ident(name) {
            return None;
        }
        members.sort();
        members.dedup();
        if members.is_empty() || members.iter().any(|member| !valid_ident(member)) {
            return None;
        }

        let mut hasher = Sha256::new();
        hasher.update(b"cermet-set-snapshot-v1");
        hash_part(&mut hasher, provider.as_bytes());
        hash_part(&mut hasher, name.as_bytes());
        for member in &members {
            hash_part(&mut hasher, member.as_bytes());
        }
        let digest = format!("sha256:{}", crate::util::hex(&hasher.finalize()));
        Some(Self {
            provider: provider.to_string(),
            name: name.to_string(),
            digest,
            members,
        })
    }

    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn members(&self) -> &[String] {
        &self.members
    }

    /// Reject a resolver that returns a snapshot under the wrong lookup key or with inconsistent
    /// content. Resolver output is authority, so callers validate it before use.
    pub fn is_for(&self, provider: &str, name: &str, digest: &str) -> bool {
        self.provider == provider
            && self.name == name
            && self.digest == digest
            && Self::new(provider, name, self.members.clone()).as_ref() == Some(self)
    }
}

fn hash_part(hasher: &mut Sha256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn valid_ident(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

pub fn valid_snapshot_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

/// Engine-agnostic immutable sentence-set lookup. An implementation that changes its current
/// expansion must retain prior snapshots by digest so standing rules keep their exact coverage.
pub trait SetResolver: Send + Sync {
    fn current_snapshot(&self, provider: &str, set: &str) -> Option<SetSnapshot>;

    fn snapshot(&self, provider: &str, set: &str, digest: &str) -> Option<SetSnapshot> {
        self.current_snapshot(provider, set)
            .filter(|snapshot| snapshot.is_for(provider, set, digest))
    }

    fn named_snapshot(&self, _provider: &str, _set: &str, _name: &str) -> Option<SetSnapshot> {
        None
    }
}

#[derive(Default)]
pub struct EmptySetResolver;

impl SetResolver for EmptySetResolver {
    fn current_snapshot(&self, _provider: &str, _set: &str) -> Option<SetSnapshot> {
        None
    }
}

#[derive(Default)]
pub struct VendoredSetResolver;

impl SetResolver for VendoredSetResolver {
    fn current_snapshot(&self, provider: &str, set: &str) -> Option<SetSnapshot> {
        current_snapshot_from_catalog(catalog(), provider, set)
    }

    fn snapshot(&self, provider: &str, set: &str, digest: &str) -> Option<SetSnapshot> {
        snapshot_from_catalog(catalog(), provider, set, digest)
    }

    fn named_snapshot(&self, provider: &str, set: &str, name: &str) -> Option<SetSnapshot> {
        named_snapshot_from_catalog(catalog(), provider, set, name)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetCatalog {
    providers: BTreeMap<String, BTreeMap<String, SetDefinition>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetDefinition {
    #[serde(default)]
    members: Vec<String>,
    #[serde(default)]
    include: Vec<String>,
    #[serde(default)]
    history: BTreeMap<String, HistoricalSetDefinition>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalSetDefinition {
    members: Vec<String>,
}

fn catalog() -> &'static SetCatalog {
    static CATALOG: OnceLock<SetCatalog> = OnceLock::new();
    CATALOG
        .get_or_init(|| catalog_from_str(VENDORED_SETS).expect("vendored set catalog must parse"))
}

fn catalog_from_str(text: &str) -> Result<SetCatalog, serde_yaml::Error> {
    serde_yaml::from_str(text)
}

fn current_snapshot_from_catalog(
    catalog: &SetCatalog,
    provider: &str,
    set: &str,
) -> Option<SetSnapshot> {
    let sets = catalog.providers.get(provider)?;
    SetSnapshot::new(provider, set, expand(sets, set, &mut HashSet::new())?)
}

fn named_snapshot_from_catalog(
    catalog: &SetCatalog,
    provider: &str,
    set: &str,
    name: &str,
) -> Option<SetSnapshot> {
    if !valid_ident(name) {
        return None;
    }
    let historical = catalog
        .providers
        .get(provider)?
        .get(set)?
        .history
        .get(name)?;
    SetSnapshot::new(provider, set, historical.members.clone())
}

fn snapshot_from_catalog(
    catalog: &SetCatalog,
    provider: &str,
    set: &str,
    digest: &str,
) -> Option<SetSnapshot> {
    if !valid_snapshot_digest(digest) {
        return None;
    }
    let current = current_snapshot_from_catalog(catalog, provider, set);
    if current
        .as_ref()
        .is_some_and(|snapshot| snapshot.is_for(provider, set, digest))
    {
        return current;
    }
    catalog
        .providers
        .get(provider)?
        .get(set)?
        .history
        .values()
        .filter_map(|historical| SetSnapshot::new(provider, set, historical.members.clone()))
        .find(|snapshot| snapshot.is_for(provider, set, digest))
}

fn expand(
    sets: &BTreeMap<String, SetDefinition>,
    name: &str,
    visiting: &mut HashSet<String>,
) -> Option<Vec<String>> {
    if !visiting.insert(name.to_string()) {
        return None;
    }
    let definition = sets.get(name)?;
    let mut actions = definition.members.clone();
    for included in &definition.include {
        actions.extend(expand(sets, included, visiting)?);
    }
    visiting.remove(name);
    let mut seen = HashSet::new();
    actions.retain(|action| seen.insert(action.clone()));
    Some(actions)
}

/// Expand one shipped set. Unknown providers, sets, and malformed cyclic data fail to no authority.
pub fn vendored_set_actions(provider: &str, set: &str) -> Vec<String> {
    let Some(sets) = catalog().providers.get(provider) else {
        return Vec::new();
    };
    expand(sets, set, &mut HashSet::new()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cyclic_expansion_yields_no_snapshot_authority() {
        let sets = BTreeMap::from([
            (
                "one".to_string(),
                SetDefinition {
                    members: Vec::new(),
                    include: vec!["two".into()],
                    history: BTreeMap::new(),
                },
            ),
            (
                "two".to_string(),
                SetDefinition {
                    members: Vec::new(),
                    include: vec!["one".into()],
                    history: BTreeMap::new(),
                },
            ),
        ]);

        assert!(expand(&sets, "one", &mut HashSet::new()).is_none());
    }

    #[test]
    fn catalog_history_retains_prior_snapshot_after_current_advances() {
        let catalog = catalog_from_str(
            r#"
providers:
  stripe:
    support:
      members: [lookup_customer, refund, credit_balance]
      history:
        pre_m4:
          members: [lookup_customer, refund]
"#,
        )
        .unwrap();

        let current = current_snapshot_from_catalog(&catalog, "stripe", "support").unwrap();
        let prior = named_snapshot_from_catalog(&catalog, "stripe", "support", "pre_m4").unwrap();
        assert_eq!(
            current.members(),
            ["credit_balance", "lookup_customer", "refund"]
        );
        assert_eq!(prior.members(), ["lookup_customer", "refund"]);
        assert_ne!(current.digest(), prior.digest());
        assert_eq!(
            snapshot_from_catalog(&catalog, "stripe", "support", prior.digest()),
            Some(prior),
            "the production catalog lookup must keep historical digest authority refreshable"
        );
    }
}
