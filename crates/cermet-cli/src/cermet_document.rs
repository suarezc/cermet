//! Strict pure codec for the one managed authority block in repository-root `CERMET.md`.

use std::ops::Range;

use cermet_lang::sentence::{authority_digest_for, canonical_rule_bytes, parse_rules, RuleSet};

pub const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;

const START_MARKER: &str = "<!-- cermet:authority:v1 -->";
const END_MARKER: &str = "<!-- /cermet:authority:v1 -->";
const PINNED_PREFIX: &str = "Pinned authority: `";
const PINNED_SUFFIX: &str = "` <!-- cermet:pinned:v1 -->";
const OPEN_FENCE: &str = "```cermet";
const CLOSE_FENCE: &str = "```";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityDigest(String);

impl AuthorityDigest {
    pub fn parse(text: &str) -> Result<Self, DocumentError> {
        let Some(hex) = text.strip_prefix("sha256:") else {
            return Err(DocumentError::InvalidMarker);
        };
        if hex.len() != 64
            || !hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DocumentError::InvalidMarker);
        }
        Ok(Self(text.to_string()))
    }

    pub fn from_hex(hex: &str) -> Result<Self, DocumentError> {
        Self::parse(&format!("sha256:{hex}"))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MarkerValue {
    None,
    Digest(AuthorityDigest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityMarker(MarkerValue);

impl AuthorityMarker {
    pub fn none() -> Self {
        Self(MarkerValue::None)
    }

    pub fn from_digest(digest: AuthorityDigest) -> Self {
        Self(MarkerValue::Digest(digest))
    }

    pub fn parse(text: &str) -> Result<Self, DocumentError> {
        if text == "none" {
            return Ok(Self::none());
        }
        AuthorityDigest::parse(text).map(Self::from_digest)
    }

    pub fn digest(&self) -> Option<&AuthorityDigest> {
        match &self.0 {
            MarkerValue::None => None,
            MarkerValue::Digest(digest) => Some(digest),
        }
    }

    pub fn is_none(&self) -> bool {
        self.digest().is_none()
    }

    pub fn as_str(&self) -> &str {
        match &self.0 {
            MarkerValue::None => "none",
            MarkerValue::Digest(digest) => digest.as_str(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DocumentError {
    TooLarge,
    InvalidEncoding,
    InvalidControl,
    InvalidEnvelope,
    InvalidMarker,
    InvalidBody(String),
    NonCanonicalBody,
}

impl std::fmt::Display for DocumentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooLarge => write!(f, "CERMET.md exceeds the 1 MiB limit"),
            Self::InvalidEncoding => write!(f, "CERMET.md must be UTF-8 without a BOM"),
            Self::InvalidControl => write!(
                f,
                "CERMET.md must use LF and contain no disallowed controls"
            ),
            Self::InvalidEnvelope => write!(f, "CERMET.md has an invalid managed-block envelope"),
            Self::InvalidMarker => write!(f, "CERMET.md has an invalid pinned authority marker"),
            Self::InvalidBody(reason) => {
                write!(f, "CERMET.md has an invalid authority body: {reason}")
            }
            Self::NonCanonicalBody => write!(f, "CERMET.md authority body is not canonical"),
        }
    }
}

impl std::error::Error for DocumentError {}

pub struct ManagedDocument<'a> {
    source: &'a [u8],
    body: &'a str,
    marker: AuthorityMarker,
    managed: Range<usize>,
}

impl<'a> ManagedDocument<'a> {
    pub fn parse(source: &'a [u8]) -> Result<Self, DocumentError> {
        validate_document_bytes(source)?;
        let text = std::str::from_utf8(source).map_err(|_| DocumentError::InvalidEncoding)?;
        let lines = lines(text);

        let mut starts = Vec::new();
        let mut ends = Vec::new();
        let mut pinned = Vec::new();
        let mut fences = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            let value = &text[line.start..line.end];
            match value {
                START_MARKER => starts.push(index),
                END_MARKER => ends.push(index),
                OPEN_FENCE => fences.push(index),
                _ => {}
            }
            if let Ok(marker) = parse_pinned_line(value) {
                pinned.push((index, marker));
            }

            let lower = value.to_ascii_lowercase();
            if (lower.contains("cermet:authority") && value != START_MARKER && value != END_MARKER)
                || ((lower.contains("cermet:pinned") || lower.starts_with("pinned authority:"))
                    && parse_pinned_line(value).is_err())
                || (lower.contains("```cermet") && value != OPEN_FENCE)
            {
                return Err(DocumentError::InvalidEnvelope);
            }
        }

        if starts.len() != 1 || ends.len() != 1 || pinned.len() != 1 || fences.len() != 1 {
            return Err(DocumentError::InvalidEnvelope);
        }
        let start = starts[0];
        let end = ends[0];
        let (pinned_index, marker) = pinned.pop().expect("one pinned marker");
        let fence = fences[0];
        if pinned_index != start + 1
            || fence != pinned_index + 2
            || lines
                .get(pinned_index + 1)
                .map(|line| &text[line.start..line.end])
                != Some("")
            || end <= fence + 1
            || lines.get(end - 1).map(|line| &text[line.start..line.end]) != Some(CLOSE_FENCE)
        {
            return Err(DocumentError::InvalidEnvelope);
        }
        let close_count = lines[fence + 1..end]
            .iter()
            .filter(|line| &text[line.start..line.end] == CLOSE_FENCE)
            .count();
        if close_count != 1 {
            return Err(DocumentError::InvalidEnvelope);
        }

        let body_start = lines[fence].next;
        let body_end = lines[end - 1].start;
        let body = std::str::from_utf8(&source[body_start..body_end])
            .map_err(|_| DocumentError::InvalidEncoding)?;
        Ok(Self {
            source,
            body,
            marker,
            managed: lines[start].start..lines[end].end,
        })
    }

    pub fn body(&self) -> &str {
        self.body
    }

    pub fn marker(&self) -> &AuthorityMarker {
        &self.marker
    }

    pub fn rewrite(
        &self,
        marker: &AuthorityMarker,
        canonical_body: &[u8],
    ) -> Result<Vec<u8>, DocumentError> {
        let block = render_managed_block(marker, canonical_body)?;
        let final_len = self.source.len() - self.managed.len() + block.len();
        if final_len > MAX_DOCUMENT_BYTES {
            return Err(DocumentError::TooLarge);
        }
        let mut rewritten = Vec::with_capacity(final_len);
        rewritten.extend_from_slice(&self.source[..self.managed.start]);
        rewritten.extend_from_slice(&block);
        rewritten.extend_from_slice(&self.source[self.managed.end..]);
        ManagedDocument::parse(&rewritten)?;
        Ok(rewritten)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyAnalysis {
    pub rules: RuleSet,
    pub canonical_bytes: Vec<u8>,
    pub digest: AuthorityDigest,
    pub is_canonical: bool,
}

pub fn analyze_body(body: &str) -> Result<BodyAnalysis, DocumentError> {
    let rules = parse_rules(body).map_err(|error| DocumentError::InvalidBody(error.to_string()))?;
    let canonical_bytes = canonical_rule_bytes(&rules);
    let digest = AuthorityDigest::from_hex(&authority_digest_for(rules.version, &canonical_bytes))
        .expect("the core authority digest is lowercase SHA-256");
    Ok(BodyAnalysis {
        rules,
        is_canonical: canonical_bytes == body.as_bytes(),
        canonical_bytes,
        digest,
    })
}

pub fn render_managed_block(
    marker: &AuthorityMarker,
    canonical_body: &[u8],
) -> Result<Vec<u8>, DocumentError> {
    let body = std::str::from_utf8(canonical_body).map_err(|_| DocumentError::InvalidEncoding)?;
    let analysis = analyze_body(body)?;
    if !analysis.is_canonical {
        return Err(DocumentError::NonCanonicalBody);
    }
    let mut rendered = Vec::new();
    rendered.extend_from_slice(START_MARKER.as_bytes());
    rendered.extend_from_slice(b"\n");
    rendered.extend_from_slice(PINNED_PREFIX.as_bytes());
    rendered.extend_from_slice(marker.as_str().as_bytes());
    rendered.extend_from_slice(PINNED_SUFFIX.as_bytes());
    rendered.extend_from_slice(b"\n\n```cermet\n");
    rendered.extend_from_slice(canonical_body);
    rendered.extend_from_slice(b"```\n");
    rendered.extend_from_slice(END_MARKER.as_bytes());
    validate_document_bytes(&rendered)?;
    Ok(rendered)
}

pub fn render_template(
    marker: &AuthorityMarker,
    canonical_body: &[u8],
) -> Result<Vec<u8>, DocumentError> {
    let block = render_managed_block(marker, canonical_body)?;
    let mut template = b"# Cermet Authority\n\nOnly the managed block is authority input. Prose is guidance, never policy.\n\n".to_vec();
    template.extend_from_slice(&block);
    template.push(b'\n');
    if template.len() > MAX_DOCUMENT_BYTES {
        return Err(DocumentError::TooLarge);
    }
    Ok(template)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataPlaneState {
    Absent,
    Served(AuthorityDigest),
    Unserved,
    Corrupt,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RepositoryState {
    Missing,
    Invalid,
    /// Repository bytes may be structurally valid, but daemon preparation was unavailable. This is
    /// not a semantic invalid verdict and must never fabricate repository drift.
    Unknown,
    Valid {
        candidate: AuthorityDigest,
        /// Exact source-body emptiness, not canonical-output emptiness. Comments and whitespace are
        /// nonempty draft input even when preparation canonically prints an empty corpus.
        source_is_empty: bool,
        marker: AuthorityMarker,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriftState {
    Aligned,
    AlignedNoAuthority,
    UnappliedDocument,
    UnexportedLive,
    MarkerStale,
    Diverged,
    RepoMissing,
    RepoInvalid,
    DataPlaneUnserved,
    DataPlaneCorrupt,
    DataPlaneUnknown,
}

pub fn classify_drift(repository: &RepositoryState, live: &DataPlaneState) -> DriftState {
    match live {
        DataPlaneState::Unserved => return DriftState::DataPlaneUnserved,
        DataPlaneState::Corrupt => return DriftState::DataPlaneCorrupt,
        DataPlaneState::Unknown => return DriftState::DataPlaneUnknown,
        DataPlaneState::Absent | DataPlaneState::Served(_) => {}
    }
    let (candidate, source_is_empty, marker) = match repository {
        RepositoryState::Missing => return DriftState::RepoMissing,
        RepositoryState::Invalid => return DriftState::RepoInvalid,
        RepositoryState::Unknown => return DriftState::DataPlaneUnknown,
        RepositoryState::Valid {
            candidate,
            source_is_empty,
            marker,
        } => (candidate, *source_is_empty, marker),
    };
    if source_is_empty && marker.is_none() && live == &DataPlaneState::Absent {
        return DriftState::AlignedNoAuthority;
    }
    let live = match live {
        DataPlaneState::Absent => "none",
        DataPlaneState::Served(digest) => digest.as_str(),
        DataPlaneState::Unserved | DataPlaneState::Corrupt | DataPlaneState::Unknown => {
            unreachable!()
        }
    };
    let marker = marker.as_str();
    // `init` over an absent record writes an exact empty body with marker `none`. Until the first
    // export, that pair represents the absent baseline, not a third digest that can make every first
    // incremental mutation look diverged.
    let candidate = if source_is_empty && marker == "none" {
        "none"
    } else {
        candidate.as_str()
    };
    if candidate == marker && marker == live {
        DriftState::Aligned
    } else if marker == live && candidate != live {
        DriftState::UnappliedDocument
    } else if candidate == marker && live != candidate {
        DriftState::UnexportedLive
    } else if candidate == live && marker != live {
        DriftState::MarkerStale
    } else {
        DriftState::Diverged
    }
}

#[derive(Clone, Copy)]
struct Line {
    start: usize,
    end: usize,
    next: usize,
}

fn lines(text: &str) -> Vec<Line> {
    let bytes = text.as_bytes();
    let mut result = Vec::new();
    let mut start = 0;
    while start < bytes.len() {
        let relative_end = bytes[start..].iter().position(|byte| *byte == b'\n');
        match relative_end {
            Some(relative_end) => {
                let end = start + relative_end;
                result.push(Line {
                    start,
                    end,
                    next: end + 1,
                });
                start = end + 1;
            }
            None => {
                result.push(Line {
                    start,
                    end: bytes.len(),
                    next: bytes.len(),
                });
                break;
            }
        }
    }
    result
}

fn validate_document_bytes(source: &[u8]) -> Result<(), DocumentError> {
    if source.len() > MAX_DOCUMENT_BYTES {
        return Err(DocumentError::TooLarge);
    }
    if source.windows(3).any(|window| window == b"\xef\xbb\xbf")
        || std::str::from_utf8(source).is_err()
    {
        return Err(DocumentError::InvalidEncoding);
    }
    if source.iter().any(|byte| {
        *byte == b'\r' || *byte == 0x7f || (*byte < 0x20 && *byte != b'\n' && *byte != b'\t')
    }) {
        return Err(DocumentError::InvalidControl);
    }
    Ok(())
}

fn parse_pinned_line(line: &str) -> Result<AuthorityMarker, DocumentError> {
    let marker = line
        .strip_prefix(PINNED_PREFIX)
        .and_then(|rest| rest.strip_suffix(PINNED_SUFFIX))
        .ok_or(DocumentError::InvalidMarker)?;
    AuthorityMarker::parse(marker)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "<!-- cermet:authority:v1 -->\nPinned authority: `none` <!-- cermet:pinned:v1 -->\n\n```cermet\n```\n<!-- /cermet:authority:v1 -->";

    fn document(marker: &str, body: &str) -> Vec<u8> {
        format!(
            "prose-before\n<!-- cermet:authority:v1 -->\nPinned authority: `{marker}` <!-- cermet:pinned:v1 -->\n\n```cermet\n{body}```\n<!-- /cermet:authority:v1 -->\nprose-after\n"
        )
        .into_bytes()
    }

    #[test]
    fn parses_the_exact_empty_managed_block() {
        let parsed = ManagedDocument::parse(EMPTY.as_bytes()).unwrap();
        assert_eq!(parsed.marker(), &AuthorityMarker::none());
        assert_eq!(parsed.body(), "");
    }

    #[test]
    fn missing_duplicate_nested_reordered_and_lookalike_delimiters_refuse() {
        let valid = String::from_utf8(document("none", "")).unwrap();
        let cases = [
            valid.replace("<!-- cermet:authority:v1 -->\n", ""),
            format!("<!-- cermet:authority:v1 -->\n{valid}"),
            valid.replace("```cermet\n", "```cermet\n<!-- cermet:authority:v1 -->\n"),
            valid.replace(
                "<!-- cermet:authority:v1 -->\nPinned authority:",
                "Pinned authority:\n<!-- cermet:authority:v1 -->",
            ),
            valid.replace(
                "<!-- cermet:authority:v1 -->",
                "<!--  cermet:authority:v1 -->",
            ),
            valid.replace("```cermet", "```CERMET"),
            valid.replace(
                "<!-- /cermet:authority:v1 -->",
                "<!-- /cermet:authority:v2 -->",
            ),
            valid.replace("```\n<!-- /cermet", "```\n```\n<!-- /cermet"),
        ];
        for case in cases {
            assert!(
                ManagedDocument::parse(case.as_bytes()).is_err(),
                "accepted {case:?}"
            );
        }
    }

    #[test]
    fn case_variant_authority_marker_lookalikes_in_prose_refuse() {
        for lookalike in [
            "<!-- CERMET:AUTHORITY:V1 -->",
            "<!-- /Cermet:Authority:V1 -->",
            "Pinned Authority: `none` <!-- CERMET:PINNED:V1 -->",
        ] {
            let source = [lookalike.as_bytes(), b"\n", EMPTY.as_bytes()].concat();
            assert!(
                ManagedDocument::parse(&source).is_err(),
                "accepted case-variant reserved marker {lookalike:?}"
            );
        }
    }

    #[test]
    fn bom_crlf_nul_controls_invalid_utf8_and_over_cap_refuse() {
        let mut cases = vec![
            [b"\xef\xbb\xbf".as_slice(), EMPTY.as_bytes()].concat(),
            EMPTY.replace('\n', "\r\n").into_bytes(),
            EMPTY.replace("```cermet", "```cermet\0").into_bytes(),
            EMPTY.replace("```cermet", "```cermet\u{001b}").into_bytes(),
        ];
        let mut invalid_utf8 = EMPTY.as_bytes().to_vec();
        invalid_utf8[0] = 0xff;
        cases.push(invalid_utf8);
        cases.push(vec![b'x'; MAX_DOCUMENT_BYTES + 1]);
        for case in cases {
            assert!(ManagedDocument::parse(&case).is_err());
        }
    }

    #[test]
    fn exactly_cap_bytes_are_not_rejected_for_size_alone() {
        let mut source = document("none", "");
        let extra = MAX_DOCUMENT_BYTES - source.len();
        source.splice(0..0, std::iter::repeat_n(b'x', extra));
        assert_eq!(source.len(), MAX_DOCUMENT_BYTES);
        assert!(ManagedDocument::parse(&source).is_ok());
    }

    #[test]
    fn marker_syntax_is_exact_and_lowercase() {
        let digest = "a".repeat(64);
        assert_eq!(
            AuthorityMarker::parse(&format!("sha256:{digest}")).unwrap(),
            AuthorityMarker::from_digest(AuthorityDigest::from_hex(&digest).unwrap())
        );
        assert_eq!(
            AuthorityMarker::parse("none").unwrap(),
            AuthorityMarker::none()
        );
        for invalid in [
            "None".to_string(),
            "none ".to_string(),
            format!("sha256:{}", "A".repeat(64)),
            format!("sha256:{}", "a".repeat(63)),
            format!("SHA256:{}", "a".repeat(64)),
        ] {
            assert!(
                AuthorityMarker::parse(&invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn body_analysis_has_exact_empty_and_rule_digest_vectors() {
        let empty = analyze_body("").unwrap();
        assert_eq!(empty.canonical_bytes, b"");
        assert_eq!(
            empty.digest.as_str(),
            "sha256:b0852b040bc6ca4bdfee1f8e1b2383ca27855f107ef200b048138ace6b730f87"
        );
        assert!(empty.is_canonical);

        let rule = "allow stripe.refund where amount <= 5000\n";
        let analyzed = analyze_body(rule).unwrap();
        assert_eq!(analyzed.canonical_bytes, rule.as_bytes());
        assert_eq!(
            analyzed.digest.as_str(),
            "sha256:d0821ba2ddbd5399b804652d3e9c60b3e7dc76feb3b65525f88df72edb5ad650"
        );
        assert!(analyzed.is_canonical);
        assert!(
            !analyze_body(" allow   stripe.refund where amount<=5000 # draft\n")
                .unwrap()
                .is_canonical
        );
    }

    #[test]
    fn render_requires_a_canonical_body() {
        let marker = AuthorityMarker::none();
        assert!(matches!(
            render_managed_block(&marker, b" allow stripe.support\n"),
            Err(DocumentError::NonCanonicalBody)
        ));
        assert!(render_managed_block(&marker, b"allow not valid\n").is_err());
    }

    #[test]
    fn rewrite_preserves_all_prose_bytes_and_extracts_only_rules() {
        let canary = "HOSTILE_PROSE_CANARY_M1";
        let source = format!(
            "{canary}\t\n<!-- cermet:authority:v1 -->\nPinned authority: `none` <!-- cermet:pinned:v1 -->\n\n```cermet\n```\n<!-- /cermet:authority:v1 -->\n\n{canary}\n"
        );
        let parsed = ManagedDocument::parse(source.as_bytes()).unwrap();
        assert!(!parsed.body().contains(canary));
        let body = b"allow stripe.support where amount <= 5000\n";
        let digest = AuthorityMarker::from_digest(
            analyze_body(std::str::from_utf8(body).unwrap())
                .unwrap()
                .digest,
        );
        let rewritten = parsed.rewrite(&digest, body).unwrap();
        let rewritten = String::from_utf8(rewritten).unwrap();
        assert!(rewritten.starts_with(&format!("{canary}\t\n")));
        assert!(rewritten.ends_with(&format!("\n\n{canary}\n")));
        assert_eq!(rewritten.matches(canary).count(), 2);
        assert_eq!(
            ManagedDocument::parse(rewritten.as_bytes())
                .unwrap()
                .body()
                .as_bytes(),
            body
        );
    }

    #[test]
    fn template_is_exact_and_round_trips() {
        let bytes = render_template(&AuthorityMarker::none(), b"").unwrap();
        let expected = "# Cermet Authority\n\nOnly the managed block is authority input. Prose is guidance, never policy.\n\n<!-- cermet:authority:v1 -->\nPinned authority: `none` <!-- cermet:pinned:v1 -->\n\n```cermet\n```\n<!-- /cermet:authority:v1 -->\n";
        assert_eq!(bytes, expected.as_bytes());
        ManagedDocument::parse(&bytes).unwrap();
    }

    #[test]
    fn classifies_every_three_way_relation() {
        let a = AuthorityDigest::from_hex(&"a".repeat(64)).unwrap();
        let b = AuthorityDigest::from_hex(&"b".repeat(64)).unwrap();
        let c = AuthorityDigest::from_hex(&"c".repeat(64)).unwrap();
        let ma = AuthorityMarker::from_digest(a.clone());
        let mb = AuthorityMarker::from_digest(b.clone());
        let valid = |candidate, marker, source_is_empty| RepositoryState::Valid {
            candidate,
            source_is_empty,
            marker,
        };
        assert_eq!(
            classify_drift(
                &valid(a.clone(), ma.clone(), false),
                &DataPlaneState::Served(a.clone())
            ),
            DriftState::Aligned
        );
        assert_eq!(
            classify_drift(
                &valid(a.clone(), ma.clone(), false),
                &DataPlaneState::Served(b.clone())
            ),
            DriftState::UnexportedLive
        );
        assert_eq!(
            classify_drift(
                &valid(b.clone(), ma.clone(), false),
                &DataPlaneState::Served(a.clone())
            ),
            DriftState::UnappliedDocument
        );
        assert_eq!(
            classify_drift(
                &valid(a.clone(), mb, false),
                &DataPlaneState::Served(a.clone())
            ),
            DriftState::MarkerStale
        );
        assert_eq!(
            classify_drift(&valid(c, ma.clone(), false), &DataPlaneState::Served(b)),
            DriftState::Diverged
        );
        assert_eq!(
            classify_drift(&RepositoryState::Missing, &DataPlaneState::Absent),
            DriftState::RepoMissing
        );
        assert_eq!(
            classify_drift(&RepositoryState::Invalid, &DataPlaneState::Absent),
            DriftState::RepoInvalid
        );
        assert_eq!(
            classify_drift(&RepositoryState::Unknown, &DataPlaneState::Absent),
            DriftState::DataPlaneUnknown
        );
        assert_eq!(
            classify_drift(
                &valid(a.clone(), ma.clone(), false),
                &DataPlaneState::Unserved
            ),
            DriftState::DataPlaneUnserved
        );
        assert_eq!(
            classify_drift(
                &valid(a.clone(), ma.clone(), false),
                &DataPlaneState::Corrupt
            ),
            DriftState::DataPlaneCorrupt
        );
        assert_eq!(
            classify_drift(&valid(a.clone(), ma, false), &DataPlaneState::Unknown),
            DriftState::DataPlaneUnknown
        );
        assert_eq!(
            classify_drift(
                &valid(a.clone(), AuthorityMarker::none(), true),
                &DataPlaneState::Absent
            ),
            DriftState::AlignedNoAuthority
        );
        assert_eq!(
            classify_drift(
                &valid(
                    analyze_body("").unwrap().digest,
                    AuthorityMarker::none(),
                    true,
                ),
                &DataPlaneState::Served(a)
            ),
            DriftState::UnexportedLive,
            "the initialized none/empty baseline must show the first live mutation's direction"
        );
    }
}
