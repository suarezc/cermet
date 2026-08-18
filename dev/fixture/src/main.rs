//! A deterministic local Stripe fixture with a request ORACLE, for `dev/e2e`.
//!
//! It serves the two routes the harness drives — `GET /v1/charges/:id` and `POST /v1/refunds` —
//! with bodies derived from the request, and it records every request that reaches it: method,
//! path, the `Authorization` header verbatim, and the decoded form fields.
//!
//! The oracle is the point. Asserting that an ALLOWED effect arrived is the easy half; the half
//! that matters is that a DENIED effect produced **zero contact** — that the broker did not call
//! Stripe and then discard the answer, but never called at all. Only a server that can be asked
//! "how many requests have you seen, ever?" can tell those apart, so this one counts every byte of
//! traffic including requests to routes it does not serve.
//!
//! It records the `Authorization` header in full. That is deliberate and safe HERE and nowhere
//! else: the only token this process ever sees is the synthetic one `dev/e2e` mints for the run,
//! the oracle file lives in the harness's own 0700 temp root, and proving the RIGHT credential
//! reached the provider is one of the contract claims. Nothing about this program is shipped, and
//! nothing in the product may copy this shape.
//!
//! Usage:
//!   cermet-stripe-fixture --oracle <path> [--port <n>] [--ready <path>]
//!
//! With `--port 0` (the default) the kernel picks the port and the chosen one is written to
//! `--ready` (and printed), so the harness never guesses or races.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// One recorded request, in arrival order.
#[derive(Debug)]
struct Record {
    seq: u64,
    method: String,
    path: String,
    authorization: String,
    form: BTreeMap<String, String>,
    body: String,
}

struct Oracle {
    path: String,
    seen: Mutex<Vec<Record>>,
    next_seq: AtomicU64,
}

impl Oracle {
    fn record(&self, record: Record) {
        self.seen.lock().expect("oracle lock").push(record);
        self.flush();
    }

    /// Rewrite the oracle file after every request. The harness reads it between steps, so it must
    /// never have to guess whether a write is still buffered somewhere.
    fn flush(&self) {
        let seen = self.seen.lock().expect("oracle lock");
        let mut out = String::from("{\n  \"schema\": \"cermet.e2e-stripe-oracle.v1\",\n");
        out.push_str(&format!("  \"total_requests\": {},\n", seen.len()));
        out.push_str("  \"requests\": [\n");
        for (index, record) in seen.iter().enumerate() {
            out.push_str("    {");
            out.push_str(&format!("\"seq\": {}, ", record.seq));
            out.push_str(&format!("\"method\": {}, ", json_string(&record.method)));
            out.push_str(&format!("\"path\": {}, ", json_string(&record.path)));
            out.push_str(&format!(
                "\"authorization\": {}, ",
                json_string(&record.authorization)
            ));
            out.push_str(&format!("\"body\": {}, ", json_string(&record.body)));
            out.push_str("\"form\": {");
            for (position, (key, value)) in record.form.iter().enumerate() {
                if position > 0 {
                    out.push_str(", ");
                }
                out.push_str(&format!("{}: {}", json_string(key), json_string(value)));
            }
            out.push('}');
            out.push('}');
            if index + 1 < seen.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ]\n}\n");
        let temporary = format!("{}.partial", self.path);
        std::fs::write(&temporary, out.as_bytes()).expect("write oracle");
        std::fs::rename(&temporary, &self.path).expect("publish oracle");
    }
}

fn json_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for character in raw.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `application/x-www-form-urlencoded` → pairs. Only the escapes Stripe's own encoder emits.
fn parse_form(body: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    for pair in body.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = match pair.split_once('=') {
            Some(split) => split,
            None => (pair, ""),
        };
        fields.insert(percent_decode(key), percent_decode(value));
    }
    fields
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(bytes[index]);
                        index += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn respond(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Deterministic bodies: the same request always produces the same answer, and every value in the
/// answer is derived from the request, so a harness assertion can name what it expects.
fn serve(method: &str, path: &str, form: &BTreeMap<String, String>) -> (String, String) {
    let empty = String::new();
    match (method, path) {
        ("POST", "/v1/refunds") => {
            let charge = form.get("charge").unwrap_or(&empty);
            let amount = form.get("amount").unwrap_or(&empty);
            (
                "200 OK".into(),
                format!(
                    "{{\"id\": \"re_fixture_{charge}\", \"object\": \"refund\", \"charge\": \"{charge}\", \"amount\": {}, \"currency\": \"usd\", \"status\": \"succeeded\"}}",
                    if amount.is_empty() { "0" } else { amount }
                ),
            )
        }
        ("GET", p) if p.starts_with("/v1/charges/") => {
            let charge = p.trim_start_matches("/v1/charges/");
            (
                "200 OK".into(),
                format!(
                    "{{\"id\": \"{charge}\", \"object\": \"charge\", \"amount\": 10000, \"amount_refunded\": 0, \"currency\": \"usd\", \"captured\": true, \"refunded\": false, \"status\": \"succeeded\"}}"
                ),
            )
        }
        _ => (
            "404 Not Found".into(),
            format!("{{\"error\": {{\"type\": \"invalid_request_error\", \"message\": \"the fixture serves GET /v1/charges/:id and POST /v1/refunds; got {method} {path}\"}}}}"),
        ),
    }
}

fn handle(mut stream: TcpStream, oracle: &Arc<Oracle>) {
    let mut reader = BufReader::new(stream.try_clone().expect("clone stream"));
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.trim().is_empty() {
        return;
    }
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let path = parts.next().unwrap_or("").to_string();

    let mut authorization = String::new();
    let mut content_length = 0usize;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).is_err() {
            return;
        }
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            let value = value.trim();
            match name.to_ascii_lowercase().as_str() {
                "authorization" => authorization = value.to_string(),
                "content-length" => content_length = value.parse().unwrap_or(0),
                _ => {}
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }
    let body = String::from_utf8_lossy(&body).into_owned();
    let form = parse_form(&body);

    // The control routes are the harness talking to its own fixture, never provider traffic, so
    // they are answered without being counted as contact.
    if path == "/__shutdown" {
        respond(&mut stream, "200 OK", "{\"stopping\": true}");
        std::process::exit(0);
    }
    if path == "/__oracle" {
        let seen = oracle.seen.lock().expect("oracle lock");
        respond(
            &mut stream,
            "200 OK",
            &format!("{{\"total_requests\": {}}}", seen.len()),
        );
        return;
    }

    let seq = oracle.next_seq.fetch_add(1, Ordering::SeqCst);
    let (status, response_body) = serve(&method, &path, &form);
    oracle.record(Record {
        seq,
        method,
        path,
        authorization,
        form,
        body,
    });
    respond(&mut stream, &status, &response_body);
}

fn main() {
    let mut oracle_path = String::new();
    let mut ready_path = String::new();
    let mut port: u16 = 0;
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--oracle" => oracle_path = args.next().unwrap_or_default(),
            "--ready" => ready_path = args.next().unwrap_or_default(),
            "--port" => port = args.next().unwrap_or_default().parse().unwrap_or(0),
            other => {
                eprintln!("cermet-stripe-fixture: unknown argument {other}");
                std::process::exit(2);
            }
        }
    }
    if oracle_path.is_empty() {
        eprintln!("cermet-stripe-fixture: --oracle <path> is required");
        std::process::exit(2);
    }

    let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind fixture listener");
    let bound = listener.local_addr().expect("fixture local addr").port();

    let oracle = Arc::new(Oracle {
        path: oracle_path,
        seen: Mutex::new(Vec::new()),
        next_seq: AtomicU64::new(1),
    });
    // Publish an empty oracle before announcing the port, so "zero contact" is readable from the
    // very first instant the harness can reach us.
    oracle.flush();

    if !ready_path.is_empty() {
        std::fs::write(&ready_path, format!("{bound}\n")).expect("write ready file");
    }
    println!("{bound}");
    let _ = std::io::stdout().flush();

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let oracle = Arc::clone(&oracle);
                std::thread::spawn(move || handle(stream, &oracle));
            }
            Err(_) => continue,
        }
    }
}
