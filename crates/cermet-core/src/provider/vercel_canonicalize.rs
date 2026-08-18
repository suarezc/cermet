//! Narrow compiled Vercel request-field canonicalizers.

use reqwest::Method;
use serde_json::Value;

use super::{http_call_with_encoding, GenericProvider, ProviderResponse};
use crate::canonicalize::{
    CanonicalizerKind, VERCEL_TEAMS_PAGE_LIMIT, VERCEL_TEAMS_PATH, VERCEL_TEAM_ID_PREFIX,
};
use crate::evidence::{EvidenceFailure, EvidenceFailureClass};
use crate::templates::BodyEncoding;

const SUCCESS_STATUSES: &[u16] = &[200];

pub(super) fn canonicalize(
    provider: &GenericProvider,
    resolver: CanonicalizerKind,
    token: &str,
    supplied: &str,
) -> std::result::Result<String, EvidenceFailure> {
    match resolver {
        CanonicalizerKind::VercelTeamScope => team_scope(provider, token, supplied),
    }
}

/// Resolve one team SLUG to its `team_…` id.
///
/// The caller has already ruled out every canonical form ([`CanonicalizerKind::is_canonical`]), so
/// `supplied` is a slug and this always makes the read.
fn team_scope(
    provider: &GenericProvider,
    token: &str,
    slug: &str,
) -> std::result::Result<String, EvidenceFailure> {
    let listing = get(
        provider,
        token,
        &format!("{VERCEL_TEAMS_PATH}?limit={VERCEL_TEAMS_PAGE_LIMIT}"),
    )?;
    team_id_for_slug(&listing, slug)
}

/// The whole decision, as a pure projection of the listing body. The slug is matched LOCALLY here —
/// it is never interpolated into a path segment or a query value — so an agent-supplied slug has no
/// request-shaping surface to reach at all.
fn team_id_for_slug(listing: &Value, slug: &str) -> std::result::Result<String, EvidenceFailure> {
    let teams = listing
        .get("teams")
        .and_then(Value::as_array)
        .ok_or_else(|| EvidenceFailure::new(EvidenceFailureClass::Malformed))?;
    let mut resolved: Option<&str> = None;
    for team in teams {
        if team.get("slug").and_then(Value::as_str) != Some(slug) {
            continue;
        }
        let id = team
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| EvidenceFailure::new(EvidenceFailureClass::Malformed))?;
        // The value about to be frozen is enforced verbatim as the `teamId` of every credentialed
        // hop in the deploy session. A listing row that does not carry a team id in the team-id
        // shape is not something to freeze.
        if !id.starts_with(VERCEL_TEAM_ID_PREFIX) {
            return Err(EvidenceFailure::new(EvidenceFailureClass::Malformed));
        }
        // Vercel documents the slug as unique across the platform. If the listing ever says
        // otherwise, the request names two different teams and there is no right answer: deny.
        if resolved.is_some_and(|previous| previous != id) {
            return Err(EvidenceFailure::new(EvidenceFailureClass::Ambiguous));
        }
        resolved = Some(id);
    }
    resolved
        .map(str::to_string)
        .ok_or_else(|| EvidenceFailure::new(EvidenceFailureClass::ProviderNotFound))
}

fn get(
    provider: &GenericProvider,
    token: &str,
    path: &str,
) -> std::result::Result<Value, EvidenceFailure> {
    let response = http_call_with_encoding(
        &provider.egress,
        Method::GET,
        format!("{}{path}", provider.base),
        token,
        None,
        &[],
        &provider.auth,
        &provider.header_refs(),
        BodyEncoding::Json,
        SUCCESS_STATUSES,
    )
    .map_err(|_| EvidenceFailure::new(EvidenceFailureClass::ProviderUnavailable))?;
    response_body(response)
}

fn response_body(response: ProviderResponse) -> std::result::Result<Value, EvidenceFailure> {
    if response.ok {
        return Ok(response.result);
    }
    let status = response
        .result
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|status| u16::try_from(status).ok());
    let class = match status {
        Some(401) => EvidenceFailureClass::ProviderAuthentication,
        Some(403) => EvidenceFailureClass::ProviderDenied,
        Some(404) => EvidenceFailureClass::ProviderNotFound,
        Some(429) => EvidenceFailureClass::RateLimited,
        Some(500..=599) | None => EvidenceFailureClass::ProviderUnavailable,
        Some(_) => EvidenceFailureClass::Malformed,
    };
    Err(match status {
        Some(status) => EvidenceFailure::status(class, status),
        None => EvidenceFailure::new(class),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn listing() -> Value {
        json!({
            "teams": [
                { "id": "team_other", "slug": "other-team", "name": "Other" },
                { "id": "team_ours", "slug": "cermet-test-team", "name": "Cermet Test" },
            ],
            "pagination": { "count": 2, "next": null }
        })
    }

    #[test]
    fn a_known_slug_resolves_to_its_team_id() {
        assert_eq!(
            team_id_for_slug(&listing(), "cermet-test-team").unwrap(),
            "team_ours"
        );
    }

    #[test]
    fn an_unknown_slug_is_a_typed_not_found_never_a_guess() {
        assert_eq!(
            team_id_for_slug(&listing(), "cermet-tst-team")
                .unwrap_err()
                .class,
            EvidenceFailureClass::ProviderNotFound
        );
    }

    #[test]
    fn the_match_is_exact_never_a_prefix_or_a_name() {
        for near in ["cermet-test", "cermet-test-team-2", "Cermet Test", ""] {
            assert_eq!(
                team_id_for_slug(&listing(), near).unwrap_err().class,
                EvidenceFailureClass::ProviderNotFound,
                "`{near}` must not resolve"
            );
        }
    }

    #[test]
    fn a_row_whose_id_is_not_a_team_id_refuses() {
        let listing = json!({ "teams": [{ "id": "not-an-id", "slug": "s" }] });
        assert_eq!(
            team_id_for_slug(&listing, "s").unwrap_err().class,
            EvidenceFailureClass::Malformed
        );
    }

    #[test]
    fn two_rows_claiming_one_slug_refuse_rather_than_pick() {
        let listing = json!({
            "teams": [
                { "id": "team_a", "slug": "same" },
                { "id": "team_b", "slug": "same" },
            ]
        });
        assert_eq!(
            team_id_for_slug(&listing, "same").unwrap_err().class,
            EvidenceFailureClass::Ambiguous
        );
    }

    #[test]
    fn a_listing_without_teams_refuses() {
        assert_eq!(
            team_id_for_slug(&json!({ "pagination": {} }), "s")
                .unwrap_err()
                .class,
            EvidenceFailureClass::Malformed
        );
    }

    #[test]
    fn provider_status_maps_to_the_typed_failure_class() {
        let refuse = |status: u16| {
            response_body(ProviderResponse {
                ok: false,
                result: json!({ "status": status }),
                envelope: serde_json::Map::new(),
                retained: None,
                failure_class: None,
                proof: None,
            })
            .unwrap_err()
            .class
        };
        assert_eq!(refuse(401), EvidenceFailureClass::ProviderAuthentication);
        assert_eq!(refuse(403), EvidenceFailureClass::ProviderDenied);
        assert_eq!(refuse(404), EvidenceFailureClass::ProviderNotFound);
        assert_eq!(refuse(429), EvidenceFailureClass::RateLimited);
        assert_eq!(refuse(503), EvidenceFailureClass::ProviderUnavailable);
    }
}
