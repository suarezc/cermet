//! Content-addressed artifact storage.
//!
//! This store keeps retained execution output on disk, content-addressed by its SHA-256 digest, with
//! a bounded `artifacts` table indexing each stored blob by an opaque `handle`.
//!
//! The store itself is deliberately audit-FREE and key-FREE: it moves bytes and rows only. The
//! broker wraps [`store`] with an `AuditLog::record` so the digest joins the HMAC chain — that is
//! what makes post-hoc file tampering detectable (a rewritten blob no longer matches the chained
//! digest). Reads re-verify the on-disk digest and fail CLOSED on a mismatch or an unknown handle.

use std::fs;
use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::util::{hex, new_id, now_epoch, now_rfc3339};
use cermet_lang::artifacts::validate_path_grammar;
pub use cermet_lang::artifacts::{
    ArtifactAddress, ArtifactConfig, ArtifactRange, ArtifactReadSurface, ArtifactSpan,
    StoredArtifact, DEFAULT_MAX_BYTES, DEFAULT_RETENTION_DAYS, MAX_VIEW_BYTES,
};

/// Walk a `$.seg(.seg)*` capture-pointer against a JSON value (object keys only, same fail-closed
/// grammar as the template `capture` lookup in `provider.rs`). `None` on a missing prefix or segment.
/// Callers validate the grammar first ([`validate_path_grammar`]); the `?`s here stay as belt-and-
/// suspenders.
fn json_pointer_lookup<'a>(v: &'a serde_json::Value, ptr: &str) -> Option<&'a serde_json::Value> {
    let rest = ptr.strip_prefix("$.")?;
    let mut cur = v;
    for seg in rest.split('.') {
        cur = cur.get(seg)?;
    }
    Some(cur)
}

/// Create the `artifacts` index table (idempotent). Follows the greenfield `CREATE TABLE IF NOT
/// EXISTS` pattern of the other state tables.
pub fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS artifacts (
            id            TEXT PRIMARY KEY,
            request_id    TEXT NOT NULL,
            digest        TEXT NOT NULL,
            size          INTEGER NOT NULL,
            truncated     INTEGER NOT NULL,
            created_at    TEXT NOT NULL,
            created_epoch INTEGER NOT NULL
        );",
    )?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(h.finalize().as_slice())
}

/// Cap `bytes` to `max_bytes`, keeping head+tail with a marker when it overflows. Returns the bytes to
/// persist and whether truncation happened.
fn cap(bytes: &[u8], max_bytes: usize) -> (Vec<u8>, bool) {
    if bytes.len() <= max_bytes || max_bytes == 0 {
        return (bytes.to_vec(), false);
    }
    let dropped = bytes.len() - max_bytes;
    let half = max_bytes / 2;
    let marker = format!("\n...[cermet: {dropped} bytes truncated]...\n");
    let mut out = Vec::with_capacity(max_bytes + marker.len());
    out.extend_from_slice(&bytes[..half]);
    out.extend_from_slice(marker.as_bytes());
    out.extend_from_slice(&bytes[bytes.len() - (max_bytes - half)..]);
    (out, true)
}

/// A blob written to disk (content-addressed) but NOT yet indexed by an `artifacts` row. Its digest
/// is ready to chain into the audit log; the index row is inserted only AFTER that digest event is
/// recorded (see [`commit_row`]), so no row can ever exist outside the HMAC chain. A staged
/// blob whose row is never committed is harmless content-addressed garbage — unreferenced and
/// dedup-safe (a later identical store reuses it).
pub struct StagedArtifact {
    pub handle: String,
    pub digest: String,
    pub size: u64,
    pub truncated: bool,
}

/// Phase 1 of a store: cap + content-address + write the blob and derive its handle/digest. Touches
/// only the filesystem — no `artifacts` row, no audit. The caller records the digest event, THEN
/// calls [`commit_row`].
pub fn stage(root: &Path, bytes: &[u8], max_bytes: usize) -> Result<StagedArtifact> {
    let (stored, truncated) = cap(bytes, max_bytes);
    let digest = sha256_hex(&stored);
    fs::create_dir_all(root)?;
    let blob = root.join(&digest);
    if !blob.exists() {
        // Write to a temp sibling then rename, so a concurrent reader never sees a partial blob.
        let tmp = root.join(format!(".tmp-{}", new_id("blob")));
        fs::write(&tmp, &stored)?;
        // rename onto the final name; if another writer won the race the content is identical anyway.
        fs::rename(&tmp, &blob).or_else(|e| {
            let _ = fs::remove_file(&tmp);
            if blob.exists() {
                Ok(())
            } else {
                Err(e)
            }
        })?;
    }
    Ok(StagedArtifact {
        handle: new_id("art"),
        digest,
        size: bytes.len() as u64,
        truncated,
    })
}

/// Phase 2: insert the index row for a staged blob. Called ONLY after its digest event is chained.
pub fn commit_row(
    conn: &Connection,
    request_id: &str,
    staged: &StagedArtifact,
) -> Result<StoredArtifact> {
    conn.execute(
        "INSERT INTO artifacts (id, request_id, digest, size, truncated, created_at, created_epoch)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            staged.handle,
            request_id,
            staged.digest,
            staged.size as i64,
            staged.truncated as i64,
            now_rfc3339(),
            now_epoch(),
        ],
    )?;
    Ok(StoredArtifact {
        handle: staged.handle.clone(),
        digest: staged.digest.clone(),
        size: staged.size,
        truncated: staged.truncated,
    })
}

/// Store `bytes` for `request_id` (blob + index row, NO audit). A convenience over stage+commit_row
/// for callers that do not chain a digest event themselves (the unit tests here). The AUDITED write
/// path (`Broker::store_artifact_capped`) instead runs stage → record → commit_row so the digest
/// event always precedes the row.
pub fn store(
    conn: &Connection,
    root: &Path,
    request_id: &str,
    bytes: &[u8],
    max_bytes: usize,
) -> Result<StoredArtifact> {
    let staged = stage(root, bytes, max_bytes)?;
    commit_row(conn, request_id, &staged)
}

/// Retrieve a span of the blob behind `handle`. Fail closed: an unknown handle, a missing blob, or a
/// digest mismatch (post-hoc tamper) all return an error — never an empty success.
pub fn read_span(
    conn: &Connection,
    root: &Path,
    handle: &str,
    addr: Option<ArtifactAddress>,
) -> Result<ArtifactSpan> {
    let row: Option<(String, i64, i64)> = conn
        .query_row(
            "SELECT digest, size, truncated FROM artifacts WHERE id = ?1",
            params![handle],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let (digest, size, truncated) =
        row.ok_or_else(|| Error::NotFound(format!("unknown artifact handle {handle}")))?;

    let blob = root.join(&digest);
    let stored = fs::read(&blob)
        .map_err(|_| Error::NotFound(format!("artifact content missing for {handle}")))?;
    // The digest is chained in the audit log; a rewritten blob no longer matches. Refuse to serve it.
    if sha256_hex(&stored) != digest {
        return Err(Error::Integrity(format!(
            "artifact {handle} failed digest verification (content was altered on disk)"
        )));
    }

    let (unit, start, end, path, content, frame_truncated) = match addr {
        // Path addressing: parse the blob as JSON, walk the capture-pointer, return the sub-value.
        // Fail closed — a non-JSON blob or a missing segment errors (never a full-blob fallback, never
        // an empty success). The digest verification above already proves the bytes are untampered.
        Some(ArtifactAddress::Path(ptr)) => {
            // Re-validate here so even a Path constructed without from_wire fails closed.
            validate_path_grammar(&ptr)?;
            let value: serde_json::Value = serde_json::from_slice(&stored).map_err(|_| {
                Error::Invalid(format!(
                    "artifact {handle} is not JSON; a $.path read needs a JSON response body"
                ))
            })?;
            let sub = json_pointer_lookup(&value, &ptr).ok_or_else(|| {
                Error::NotFound(format!("artifact {handle} has no value at path {ptr}"))
            })?;
            let rendered = serde_json::to_string_pretty(sub).unwrap_or_else(|_| sub.to_string());
            let (content, frame_truncated) = clamp_view(rendered);
            (
                "path".to_string(),
                0,
                0,
                Some(ptr),
                content,
                frame_truncated,
            )
        }
        Some(ArtifactAddress::Range(r)) => {
            let (unit, start, end, content, frame_truncated) = slice(&stored, Some(&r))?;
            (unit, start, end, None, content, frame_truncated)
        }
        None => {
            let (unit, start, end, content, frame_truncated) = slice(&stored, None)?;
            (unit, start, end, None, content, frame_truncated)
        }
    };
    Ok(ArtifactSpan {
        handle: handle.to_string(),
        digest,
        stored_size: stored.len() as u64,
        size: size as u64,
        truncated: truncated != 0,
        unit,
        start,
        end,
        path,
        frame_truncated,
        content,
    })
}

/// Truncate `content` to at most [`MAX_VIEW_BYTES`] on a UTF-8 char boundary, reporting whether it
/// clamped. Keeps the head — a full read of a big blob thus returns its start and flags the rest as
/// range-reachable, so a legal artifact never overflows the response frame.
fn clamp_view(mut content: String) -> (String, bool) {
    if content.len() <= MAX_VIEW_BYTES {
        return (content, false);
    }
    let mut cut = MAX_VIEW_BYTES;
    while cut > 0 && !content.is_char_boundary(cut) {
        cut -= 1;
    }
    content.truncate(cut);
    (content, true)
}

/// Resolve a range against the stored bytes, returning `(unit, start, end, content, frame_truncated)`.
/// Every returned `content` is bounded by [`clamp_view`], so no read — full or ranged — can produce a
/// response larger than the transport frame.
fn slice(stored: &[u8], range: Option<&ArtifactRange>) -> Result<(String, u64, u64, String, bool)> {
    let Some(r) = range else {
        let (content, frame_truncated) = clamp_view(String::from_utf8_lossy(stored).into_owned());
        return Ok((
            "bytes".to_string(),
            0,
            stored.len() as u64,
            content,
            frame_truncated,
        ));
    };
    match r.unit.as_str() {
        "bytes" => {
            let len = stored.len() as u64;
            let start = r.start.min(len);
            let end = r.end.unwrap_or(len).clamp(start, len);
            let (content, frame_truncated) = clamp_view(
                String::from_utf8_lossy(&stored[start as usize..end as usize]).into_owned(),
            );
            Ok(("bytes".to_string(), start, end, content, frame_truncated))
        }
        "lines" => {
            let text = String::from_utf8_lossy(stored);
            let lines: Vec<&str> = text.split('\n').collect();
            let n = lines.len() as u64;
            // 1-based inclusive; a start of 0 is treated as 1.
            let start = r.start.max(1).min(n.max(1));
            let end = r.end.unwrap_or(n).clamp(start, n.max(1));
            let joined = if n == 0 {
                String::new()
            } else {
                lines[(start - 1) as usize..end as usize].join("\n")
            };
            let (content, frame_truncated) = clamp_view(joined);
            Ok(("lines".to_string(), start, end, content, frame_truncated))
        }
        other => Err(Error::Invalid(format!(
            "artifact range unit must be \"bytes\" or \"lines\", got {other:?}"
        ))),
    }
}

/// Purge rows older than the retention window and delete any blob no longer referenced by a row.
/// `<= 0` days keeps everything. Called as a startup sweep (no scheduler). Returns the row count purged.
pub fn purge_expired(
    conn: &Connection,
    root: &Path,
    retention_days: i64,
    now_epoch: i64,
) -> Result<usize> {
    if retention_days <= 0 {
        return Ok(0);
    }
    let cutoff = now_epoch - retention_days * 86_400;
    let expired: Vec<(String, String)> = {
        let mut stmt = conn.prepare("SELECT id, digest FROM artifacts WHERE created_epoch < ?1")?;
        let rows = stmt.query_map(params![cutoff], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<std::result::Result<_, _>>()?
    };
    for (id, _) in &expired {
        conn.execute("DELETE FROM artifacts WHERE id = ?1", params![id])?;
    }
    // Content is shared by digest; only remove a blob once NO row references it any more.
    for (_, digest) in &expired {
        let still: i64 = conn.query_row(
            "SELECT COUNT(*) FROM artifacts WHERE digest = ?1",
            params![digest],
            |r| r.get(0),
        )?;
        if still == 0 {
            let _ = fs::remove_file(root.join(digest));
        }
    }
    Ok(expired.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dir(std::path::PathBuf);
    impl Dir {
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn setup() -> (Connection, Dir) {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let dir = std::env::temp_dir().join(new_id("cermet-artifacts-test"));
        fs::create_dir_all(&dir).unwrap();
        (conn, Dir(dir))
    }

    #[test]
    fn store_then_read_full_roundtrips_and_addresses_by_digest() {
        let (conn, dir) = setup();
        let bytes = b"line one\nline two\nline three";
        let s = store(&conn, dir.path(), "rq-1", bytes, DEFAULT_MAX_BYTES).unwrap();
        assert!(!s.truncated);
        assert_eq!(s.size, bytes.len() as u64);
        // Content-addressed: the on-disk file name is the digest.
        assert!(dir.path().join(&s.digest).exists());

        let span = read_span(&conn, dir.path(), &s.handle, None).unwrap();
        assert_eq!(span.content, "line one\nline two\nline three");
        assert_eq!(span.digest, s.digest);
        assert!(!span.truncated);
    }

    #[test]
    fn unknown_handle_fails_closed_never_empty_success() {
        let (conn, dir) = setup();
        let err = read_span(&conn, dir.path(), "art_does_not_exist", None).unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
    }

    #[test]
    fn overflow_keeps_head_and_tail_and_marks_truncated() {
        let (conn, dir) = setup();
        // 1000 bytes, cap at 100 → head 50 + marker + tail 50, truncated.
        let bytes: Vec<u8> = (0..1000u32).map(|i| b'a' + (i % 26) as u8).collect();
        let s = store(&conn, dir.path(), "rq-1", &bytes, 100).unwrap();
        assert!(s.truncated);
        assert_eq!(s.size, 1000, "size records the ORIGINAL length");
        let span = read_span(&conn, dir.path(), &s.handle, None).unwrap();
        assert!(
            span.content.contains("truncated"),
            "marker present: {}",
            span.content
        );
        // Head is the first bytes, tail is the last bytes of the original.
        assert!(span
            .content
            .starts_with(std::str::from_utf8(&bytes[..50]).unwrap()));
        assert!(span
            .content
            .ends_with(std::str::from_utf8(&bytes[950..]).unwrap()));
    }

    #[test]
    fn byte_range_returns_the_requested_window() {
        let (conn, dir) = setup();
        let s = store(&conn, dir.path(), "rq-1", b"0123456789", DEFAULT_MAX_BYTES).unwrap();
        let span = read_span(
            &conn,
            dir.path(),
            &s.handle,
            Some(ArtifactAddress::Range(ArtifactRange {
                unit: "bytes".into(),
                start: 2,
                end: Some(5),
            })),
        )
        .unwrap();
        assert_eq!(span.content, "234");
        assert_eq!((span.start, span.end), (2, 5));
        // An out-of-range window on a KNOWN handle clamps to empty (still a success).
        let span = read_span(
            &conn,
            dir.path(),
            &s.handle,
            Some(ArtifactAddress::Range(ArtifactRange {
                unit: "bytes".into(),
                start: 999,
                end: None,
            })),
        )
        .unwrap();
        assert_eq!(span.content, "");
    }

    #[test]
    fn line_range_is_one_based_inclusive() {
        let (conn, dir) = setup();
        let s = store(
            &conn,
            dir.path(),
            "rq-1",
            b"a\nb\nc\nd\ne",
            DEFAULT_MAX_BYTES,
        )
        .unwrap();
        let span = read_span(
            &conn,
            dir.path(),
            &s.handle,
            Some(ArtifactAddress::Range(ArtifactRange {
                unit: "lines".into(),
                start: 2,
                end: Some(4),
            })),
        )
        .unwrap();
        assert_eq!(span.content, "b\nc\nd");
        assert_eq!((span.start, span.end), (2, 4));
    }

    #[test]
    fn tampered_blob_fails_digest_verification() {
        let (conn, dir) = setup();
        let s = store(
            &conn,
            dir.path(),
            "rq-1",
            b"trusted output",
            DEFAULT_MAX_BYTES,
        )
        .unwrap();
        // Rewrite the content-addressed file behind its back.
        fs::write(dir.path().join(&s.digest), b"tampered output!").unwrap();
        let err = read_span(&conn, dir.path(), &s.handle, None).unwrap_err();
        assert!(matches!(err, Error::Integrity(_)), "got {err:?}");
    }

    #[test]
    fn purge_removes_expired_rows_and_unreferenced_blobs() {
        let (conn, dir) = setup();
        let s = store(&conn, dir.path(), "rq-1", b"old output", DEFAULT_MAX_BYTES).unwrap();
        let blob = dir.path().join(&s.digest);
        // Backdate the row well beyond the window.
        conn.execute(
            "UPDATE artifacts SET created_epoch = ?1 WHERE id = ?2",
            params![now_epoch() - 200 * 86_400, s.handle],
        )
        .unwrap();
        let purged = purge_expired(&conn, dir.path(), 90, now_epoch()).unwrap();
        assert_eq!(purged, 1);
        assert!(!blob.exists(), "the now-unreferenced blob is deleted");
        assert!(matches!(
            read_span(&conn, dir.path(), &s.handle, None).unwrap_err(),
            Error::NotFound(_)
        ));
    }

    #[test]
    fn purge_keeps_a_blob_still_referenced_by_a_fresh_row() {
        let (conn, dir) = setup();
        // Two handles, identical content → one shared blob.
        let a = store(&conn, dir.path(), "rq-1", b"shared", DEFAULT_MAX_BYTES).unwrap();
        let b = store(&conn, dir.path(), "rq-2", b"shared", DEFAULT_MAX_BYTES).unwrap();
        assert_eq!(a.digest, b.digest, "identical content dedupes to one blob");
        conn.execute(
            "UPDATE artifacts SET created_epoch = ?1 WHERE id = ?2",
            params![now_epoch() - 200 * 86_400, a.handle],
        )
        .unwrap();
        let purged = purge_expired(&conn, dir.path(), 90, now_epoch()).unwrap();
        assert_eq!(purged, 1);
        // b is fresh and still references the shared blob → the blob survives.
        assert!(dir.path().join(&b.digest).exists());
        assert!(read_span(&conn, dir.path(), &b.handle, None).is_ok());
    }

    #[test]
    fn a_full_read_over_a_big_blob_clamps_to_the_frame_and_flags_it() {
        // A legally stored blob larger than the inline view budget must READ (never frame-error): a
        // full read returns the head up to MAX_VIEW_BYTES with frame_truncated=true and the true
        // stored_size, so the caller knows to range for the rest.
        let (conn, dir) = setup();
        let big = vec![b'x'; MAX_VIEW_BYTES + 4096];
        // Store it uncapped (cap above its length) so the STORE keeps every byte — the read is what
        // must clamp, not the store.
        let s = store(&conn, dir.path(), "rq-1", &big, big.len() + 1).unwrap();
        assert!(!s.truncated, "the blob itself is stored whole");

        let span = read_span(&conn, dir.path(), &s.handle, None).unwrap();
        assert!(
            span.frame_truncated,
            "a full read wider than the frame is clamped"
        );
        assert_eq!(
            span.content.len(),
            MAX_VIEW_BYTES,
            "the head up to the view budget is returned"
        );
        assert_eq!(
            span.stored_size,
            big.len() as u64,
            "the true total size is reported"
        );

        // The rest is reachable by an explicit byte range — no data is lost, only paged.
        let tail = read_span(
            &conn,
            dir.path(),
            &s.handle,
            Some(ArtifactAddress::Range(ArtifactRange {
                unit: "bytes".into(),
                start: MAX_VIEW_BYTES as u64,
                end: None,
            })),
        )
        .unwrap();
        assert!(!tail.frame_truncated, "the small tail window fits");
        assert_eq!(tail.content.len(), 4096);
    }

    #[test]
    fn path_addressing_returns_a_single_nested_field() {
        let (conn, dir) = setup();
        let body = br#"{"deployment":{"url":"https://x.app","meta":{"id":"dpl_1"}},"logs":[1,2]}"#;
        let s = store(&conn, dir.path(), "rq-1", body, DEFAULT_MAX_BYTES).unwrap();

        // A scalar leaf comes back as its serialized JSON (quoted string).
        let span = read_span(
            &conn,
            dir.path(),
            &s.handle,
            Some(ArtifactAddress::Path("$.deployment.url".into())),
        )
        .unwrap();
        assert_eq!(span.unit, "path");
        assert_eq!(span.path.as_deref(), Some("$.deployment.url"));
        assert_eq!(span.content, "\"https://x.app\"");

        // A nested object leaf comes back serialized (pretty).
        let span = read_span(
            &conn,
            dir.path(),
            &s.handle,
            Some(ArtifactAddress::Path("$.deployment.meta".into())),
        )
        .unwrap();
        assert!(span.content.contains("\"id\""), "got {}", span.content);
        assert!(span.content.contains("dpl_1"));
    }

    #[test]
    fn path_missing_segment_fails_closed_not_empty() {
        let (conn, dir) = setup();
        let s = store(
            &conn,
            dir.path(),
            "rq-1",
            br#"{"a":{"b":1}}"#,
            DEFAULT_MAX_BYTES,
        )
        .unwrap();
        // A missing segment is a fail-closed NotFound — not an empty success, not a full-blob fallback.
        let err = read_span(
            &conn,
            dir.path(),
            &s.handle,
            Some(ArtifactAddress::Path("$.a.zzz".into())),
        )
        .unwrap_err();
        assert!(matches!(err, Error::NotFound(_)), "got {err:?}");
        // A pointer missing the `$.` prefix is a grammar rejection.
        assert!(matches!(
            read_span(
                &conn,
                dir.path(),
                &s.handle,
                Some(ArtifactAddress::Path("a.b".into()))
            )
            .unwrap_err(),
            Error::Invalid(_)
        ));
    }

    #[test]
    fn path_over_non_json_blob_fails_closed() {
        let (conn, dir) = setup();
        let s = store(
            &conn,
            dir.path(),
            "rq-1",
            b"not json at all",
            DEFAULT_MAX_BYTES,
        )
        .unwrap();
        let err = read_span(
            &conn,
            dir.path(),
            &s.handle,
            Some(ArtifactAddress::Path("$.anything".into())),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Invalid(_)), "got {err:?}");
    }

    #[test]
    fn from_wire_rejects_malformed_path_grammar() {
        // The shared boundary every wire surface funnels through — a Path must not even be
        // constructible from a malformed pointer.
        for bad in ["$.", "$..x", "$.a.", "a.b", "$", ""] {
            assert!(
                matches!(
                    ArtifactAddress::from_wire(None, Some(bad.into())),
                    Err(Error::Invalid(_))
                ),
                "from_wire must reject {bad:?}"
            );
        }
        assert!(ArtifactAddress::from_wire(None, Some("$.a.b".into())).is_ok());
    }

    #[test]
    fn read_span_rejects_a_directly_constructed_malformed_path() {
        // Defense in depth: a Path built WITHOUT from_wire must still fail closed in read_span —
        // never resolve against empty-string JSON keys.
        let (conn, dir) = setup();
        let body = br#"{"":{"x":"leak"},"a":{"":"leak2"}}"#;
        let s = store(&conn, dir.path(), "rq-1", body, DEFAULT_MAX_BYTES).unwrap();
        for bad in ["$.", "$..x", "$.a.", "a.b"] {
            let err = read_span(
                &conn,
                dir.path(),
                &s.handle,
                Some(ArtifactAddress::Path(bad.into())),
            )
            .unwrap_err();
            assert!(
                matches!(err, Error::Invalid(_)),
                "path {bad:?} must fail closed as Invalid, got {err:?}"
            );
        }
    }

    #[test]
    fn from_wire_rejects_both_range_and_path() {
        assert!(ArtifactAddress::from_wire(None, None).unwrap().is_none());
        assert!(matches!(
            ArtifactAddress::from_wire(
                Some(ArtifactRange {
                    unit: "bytes".into(),
                    start: 0,
                    end: None
                }),
                Some("$.x".into()),
            ),
            Err(Error::Invalid(_))
        ));
        assert!(matches!(
            ArtifactAddress::from_wire(None, Some("$.x".into())).unwrap(),
            Some(ArtifactAddress::Path(_))
        ));
    }

    #[test]
    fn zero_retention_disables_purge() {
        let (conn, dir) = setup();
        let s = store(&conn, dir.path(), "rq-1", b"keep", DEFAULT_MAX_BYTES).unwrap();
        conn.execute(
            "UPDATE artifacts SET created_epoch = ?1 WHERE id = ?2",
            params![0, s.handle],
        )
        .unwrap();
        assert_eq!(purge_expired(&conn, dir.path(), 0, now_epoch()).unwrap(), 0);
        assert!(read_span(&conn, dir.path(), &s.handle, None).is_ok());
    }
}
