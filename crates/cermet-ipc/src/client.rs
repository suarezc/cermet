//! A thin synchronous client of the cermetd unix sockets: one request frame → one response frame,
//! honoring the codec's 64 KiB request / 4 MiB response caps. This is the keyless transport that lets
//! `cermet-app` drive the broker over `ctl.sock` instead of embedding its own vault — the client
//! holds NO master key and opens NO database.

use std::io;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;

use crate::codec::{self, read_response_frame, write_frame};

/// The default read/write deadline installed by [`SocketClient::connect`]: a caller that
/// forgets to set one still cannot hang forever. Conservative — above any real ctl op's latency.
/// The shared per-call inactivity bound every `SocketClient` installs by default. PUBLIC because
/// the MCP server derives its shutdown kill-join from this — one daemon RPC is the honest horizon
/// for joining a started worker — so the relationship is enforced, not a comment.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// A connected client over one cermetd socket (e.g. `ctl.sock`). One in-flight request at a time:
/// [`SocketClient::call`] writes a request frame then reads exactly one response frame.
pub struct SocketClient {
    stream: UnixStream,
}

impl SocketClient {
    /// Connect to the socket at `path`. Fails closed (returns the OS error) if the socket is absent,
    /// not a socket, or unreachable — there is no fallback to an embedded broker. A conservative
    /// default read/write deadline is installed so a caller who forgets [`set_timeout`] can
    /// never hang forever; clear it explicitly with `set_timeout(None)`. NOTE: this bounds read/write
    /// INACTIVITY, not connect — std `UnixStream` has no connect timeout, so an async caller needing
    /// an absolute connect deadline should use a tokio transport (see cermet-app's `CtlBrokerClient`).
    ///
    /// [`set_timeout`]: SocketClient::set_timeout
    pub fn connect(path: &Path) -> io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(DEFAULT_CALL_TIMEOUT))?;
        stream.set_write_timeout(Some(DEFAULT_CALL_TIMEOUT))?;
        Ok(Self { stream })
    }

    /// Override the read + write deadline. `None` clears them (explicitly choosing to block).
    pub fn set_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(dur)?;
        self.stream.set_write_timeout(dur)
    }

    /// Send one request frame (bounded by the 64 KiB request cap) and read one response frame
    /// (bounded by the 4 MiB response cap), returning the decoded JSON value. The caller interprets
    /// the envelope (see [`view_result`] for the uniform `ok`/`error` shape).
    pub fn call<R: Serialize>(&mut self, req: &R) -> codec::Result<Value> {
        write_frame(&mut self.stream, req)?;
        read_response_frame(&mut self.stream)
    }
}

/// Decode the uniform ctl envelope into a broker-`Reply`-shaped result: `Ok` carries the
/// `view` re-serialized as a JSON string (so a caller can reconstruct the in-process broker reply
/// with one decode path), `Err` carries the `reason`. A response without the uniform envelope (a
/// legacy per-op kind such as `pending`/`approved`, or a malformed body) is surfaced as an error —
/// the uniform decoder is intentionally strict so a missing/renamed field fails closed rather than
/// silently reading as success.
///
/// The envelope's `reason` is the BARE payload and its `code` is the error CLASS, so the
/// `Err(String)` here is class-less by contract. A caller that needs the class reads `code` (or,
/// with `cermet-lang` in scope, rebuilds the typed error via `Error::from_wire`) — never by
/// re-prefixing this string.
pub fn view_result(resp: &Value) -> Result<String, String> {
    match resp.get("kind").and_then(Value::as_str) {
        // An `ok` with NO `view` is a malformed success, NOT an empty one — fail closed
        // rather than silently returning "null" as a successful reply.
        Some("ok") => match resp.get("view") {
            Some(view) => Ok(view.to_string()),
            None => Err("malformed ok envelope: missing view".to_string()),
        },
        Some("error") => Err(resp
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("ctl error")
            .to_string()),
        other => Err(format!("unexpected ctl response kind: {other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{read_frame, write_response_frame};
    use crate::ctl::CtlRequest;
    use serde_json::json;
    use std::os::unix::net::UnixListener;
    use std::thread;
    use tempfile::tempdir;

    #[test]
    fn client_roundtrips_a_request_and_reads_the_uniform_envelope() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ctl.sock");
        let listener = UnixListener::bind(&path).unwrap();

        // Stub server: read one CtlRequest, assert it decoded, reply with the uniform ok-envelope.
        let server = thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let req: CtlRequest = read_frame(&mut conn).unwrap();
            assert_eq!(req, CtlRequest::Doctor, "server saw the framed request");
            write_response_frame(
                &mut conn,
                &json!({"kind":"ok","view":[{"session_id":"s1"}]}),
            )
            .unwrap();
        });

        let mut client = SocketClient::connect(&path).expect("connect");
        client.set_timeout(Some(Duration::from_secs(5))).unwrap();
        let resp = client.call(&CtlRequest::Doctor).expect("call");
        assert_eq!(resp["kind"], "ok");
        let view = view_result(&resp).expect("ok envelope -> view string");
        assert!(
            view.contains("session_id"),
            "view carries the payload: {view}"
        );

        server.join().unwrap();
    }

    #[test]
    fn view_result_maps_ok_error_and_rejects_non_envelope() {
        assert_eq!(
            view_result(&json!({"kind":"ok","view":{"ok":true}})).unwrap(),
            "{\"ok\":true}"
        );
        assert_eq!(
            view_result(&json!({"kind":"error","reason":"nope"})).unwrap_err(),
            "nope"
        );
        // An `ok` with no `view` is malformed, not an empty success.
        assert!(
            view_result(&json!({"kind":"ok"})).is_err(),
            "ok-without-view fails closed"
        );
        // A legacy per-op kind / non-envelope body is an error to the uniform decoder (fail closed).
        assert!(view_result(&json!({"kind":"pending","grants":[]})).is_err());
        assert!(view_result(&json!({"nope":1})).is_err());
    }
}
