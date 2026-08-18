//! Value-tree redaction.

use serde_json::Value;

/// Redaction is EXACT-SECRET only. Cermet's custody claim is over the credentials in its own
/// vault, and `vault.all_secrets()` enumerates every one of them exactly, so an ambient
/// token-SHAPE pattern list (`vercel_…`, `gh[pousr]_…`, `github_…`, `Bearer …`) would only ever
/// fire on strings that are NOT ours to protect, at the cost of corrupting legitimate provider
/// payloads that happen to match.
fn redact_str(input: &str, secrets: &[&str]) -> String {
    let mut out = input.to_string();
    for s in secrets {
        if !s.is_empty() {
            out = out.replace(s, "[SECRET_REDACTED]");
        }
    }
    out
}

/// Recursively redact every string leaf in `value`.
pub fn redact_value(value: &mut Value, secrets: &[String]) {
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
    redact_value_refs(value, &secrets);
}

/// Recursively redact string leaves without cloning plaintext secrets into ordinary `String`s.
pub fn redact_value_refs(value: &mut Value, secrets: &[&str]) {
    match value {
        Value::String(s) => *s = redact_str(s, secrets),
        Value::Array(items) => items.iter_mut().for_each(|v| redact_value_refs(v, secrets)),
        Value::Object(map) => {
            let fields = std::mem::take(map);
            for (key, mut child) in fields {
                redact_value_refs(&mut child, secrets);
                map.insert(redact_str(&key, secrets), child);
            }
        }
        _ => {}
    }
}

pub fn redacted(mut value: Value, secrets: &[String]) -> Value {
    redact_value(&mut value, secrets);
    value
}

/// Owned redacted result for callers that hold secrets behind zeroizing wrappers.
pub fn redacted_refs(mut value: Value, secrets: &[&str]) -> Value {
    redact_value_refs(&mut value, secrets);
    value
}

/// Byte-level redaction over a raw response body: the SAME vault-secret pass the narrowed result
/// gets (the exact vault secret set), applied to body bytes before they are stored as an artifact
/// or written back to a relay client. Also replaces each secret's JSON-ESCAPED form — a serialized
/// JSON body carries a secret containing `"`/`\` escaped, and the raw needle alone would miss it.
///
/// This is a BYTE operation and decodes nothing. A body is opaque bytes — it may be one fixed-size
/// read out of a larger stream, or not text at all — and a `String::from_utf8_lossy` round-trip
/// would rewrite every multi-byte character that happened to straddle a read boundary into U+FFFD,
/// secret or no secret. Vault secrets and grant handles are ASCII, so searching and splicing raw
/// bytes loses nothing and makes that corruption impossible by construction: a body containing no
/// vault secret is returned byte for byte.
pub fn redact_body_bytes(bytes: &[u8], secrets: &[String]) -> Vec<u8> {
    let secrets: Vec<&str> = secrets.iter().map(String::as_str).collect();
    redact_body_bytes_refs(bytes, &secrets)
}

/// Byte-level body redaction without cloning plaintext secrets.
pub fn redact_body_bytes_refs(bytes: &[u8], secrets: &[&str]) -> Vec<u8> {
    let mut redacted: Option<Vec<u8>> = None;
    for s in secrets {
        if s.is_empty() {
            continue;
        }
        // Escaped form first, then the raw one — the order the string pass used.
        let escaped = json_escaped(s);
        let mut needles: Vec<&[u8]> = Vec::with_capacity(2);
        if escaped != *s {
            needles.push(escaped.as_bytes());
        }
        needles.push(s.as_bytes());
        for needle in needles {
            let replaced = replace_bytes(redacted.as_deref().unwrap_or(bytes), needle);
            if let Some(next) = replaced {
                redacted = Some(next);
            }
        }
    }
    redacted.unwrap_or_else(|| bytes.to_vec())
}

const REDACTED_MARKER: &[u8] = b"[SECRET_REDACTED]";

/// The first occurrence of `needle` in `haystack` at or after `from`.
fn find_bytes(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    (from..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// Replace every occurrence of `needle`, or `None` when it does not occur — so the overwhelmingly
/// common case (a body with no vault secret in it) is not copied at all, and cannot be altered.
fn replace_bytes(haystack: &[u8], needle: &[u8]) -> Option<Vec<u8>> {
    let mut at = find_bytes(haystack, needle, 0)?;
    let mut out = Vec::with_capacity(haystack.len());
    let mut cursor = 0;
    loop {
        out.extend_from_slice(&haystack[cursor..at]);
        out.extend_from_slice(REDACTED_MARKER);
        cursor = at + needle.len();
        match find_bytes(haystack, needle, cursor) {
            Some(next) => at = next,
            None => break,
        }
    }
    out.extend_from_slice(&haystack[cursor..]);
    Some(out)
}

/// The JSON string-literal form of `s`, without the surrounding quotes — how `s` appears inside a
/// serialized JSON body.
pub(crate) fn json_escaped(s: &str) -> String {
    let quoted = Value::String(s.to_string()).to_string();
    quoted[1..quoted.len() - 1].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_exact_secret_in_nested_leaf() {
        let secrets = vec!["vercel_demo_secret_123456789".to_string()];
        let v = json!({ "outer": { "token": "vercel_demo_secret_123456789", "n": 1 } });
        let out = redacted(v, &secrets);
        assert_eq!(out["outer"]["token"], json!("[SECRET_REDACTED]"));
        assert_eq!(out["outer"]["n"], json!(1));
    }

    #[test]
    fn secret_containing_json_punctuation_does_not_corrupt() {
        let secrets = vec!["pa:ss\"word}".to_string()];
        let v = json!({ "a": "pa:ss\"word}", "b": "ok" });
        let out = redacted(v, &secrets);
        assert_eq!(out["a"], json!("[SECRET_REDACTED]"));
        assert_eq!(out["b"], json!("ok"));
    }

    #[test]
    fn every_nonempty_exact_secret_is_removed_from_keys_values_and_bytes() {
        let secrets = vec!["x".to_string()];
        let value = redacted(json!({"x": "x"}), &secrets);
        assert_eq!(value, json!({"[SECRET_REDACTED]": "[SECRET_REDACTED]"}));
        assert_eq!(
            redact_body_bytes(br#"{"x":"x"}"#, &secrets),
            br#"{"[SECRET_REDACTED]":"[SECRET_REDACTED]"}"#
        );

        assert_eq!(
            redacted(json!("unchanged"), &[String::new()]),
            json!("unchanged")
        );
    }

    /// A response body is opaque BYTES. The relay pumps it in fixed-size reads, so a multi-byte
    /// character routinely straddles a read boundary — and a decode-per-chunk would turn `✓` into
    /// U+FFFD even with no secret anywhere in it. Nothing here decodes, so a chunk that contains
    /// no vault secret comes out byte-identical, whatever it is.
    #[test]
    fn a_body_chunk_without_a_secret_is_byte_identical() {
        let body: &[u8] = b"a\xE2\x9C\x93b"; // "a✓b"
        let secrets = vec!["vercel_tok_absent".to_string()];
        assert_eq!(redact_body_bytes(body, &secrets), body);

        // The same body split mid-character across two independent chunks: redacting each half
        // and concatenating must reproduce the original byte for byte.
        for split in 1..body.len() {
            let (head, tail) = body.split_at(split);
            let mut rejoined = redact_body_bytes(head, &secrets);
            rejoined.extend_from_slice(&redact_body_bytes(tail, &secrets));
            assert_eq!(rejoined, body, "split at {split} altered the bytes");
        }
    }

    /// Non-text bodies pass through too — an invalid-UTF-8 byte is not ours to rewrite.
    #[test]
    fn a_non_utf8_body_is_not_rewritten() {
        let body: &[u8] = &[0xff, 0xfe, 0x00, 0x41, 0x80];
        assert_eq!(redact_body_bytes(body, &["s".to_string()]), body);
    }

    /// ...and a secret still goes, in raw and JSON-escaped form, with the surrounding bytes intact.
    #[test]
    fn a_secret_is_still_removed_from_raw_bytes() {
        let secrets = vec!["tok\"1".to_string()];
        assert_eq!(
            redact_body_bytes("\u{2713}tok\"1\u{2713}".as_bytes(), &secrets),
            "\u{2713}[SECRET_REDACTED]\u{2713}".as_bytes(),
        );
        // The JSON-escaped spelling of the same secret, as it lands inside a serialized body.
        assert_eq!(
            redact_body_bytes(br#"{"a":"tok\"1"}"#, &secrets),
            br#"{"a":"[SECRET_REDACTED]"}"#,
        );
        // Every occurrence, not just the first.
        assert_eq!(
            redact_body_bytes(b"tok\"1 tok\"1", &secrets),
            b"[SECRET_REDACTED] [SECRET_REDACTED]",
        );
    }

    #[test]
    fn a_string_that_merely_looks_like_a_token_is_left_alone() {
        // A credential that is not in our vault is not ours to redact, and mangling it corrupts
        // the receipt.
        let out = redacted(json!({ "hdr": "Bearer abcdef123456" }), &[]);
        assert_eq!(out["hdr"], json!("Bearer abcdef123456"));
    }
}
