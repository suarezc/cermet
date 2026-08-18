use rand::Rng;

/// Type-tagged random id, e.g. `evt_3f8a...`.
pub fn new_id(prefix: &str) -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill(&mut bytes);
    format!("{prefix}_{}", hex(&bytes))
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn now_rfc3339() -> String {
    use time::OffsetDateTime;
    OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

/// Current wall-clock as Unix epoch seconds.
pub fn now_epoch() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

/// Format a Unix epoch second in the same RFC3339 shape `now_rfc3339` produces. Used by the audit
/// `record_at` variant so a budget event's stored `ts` is the single captured `decision_at_epoch`
/// (not a re-sampled clock).
pub fn rfc3339_of_epoch(epoch: i64) -> String {
    use time::OffsetDateTime;
    OffsetDateTime::from_unix_timestamp(epoch)
        .ok()
        .and_then(|t| {
            t.format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_default()
}
