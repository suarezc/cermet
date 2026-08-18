//! Bounded tool calls honor their advertised wait AT THE STDIO RESPONSE BOUNDARY, even with
//! concurrent long-running background runs sharing the ONE stdio connection.
//!
//! This drives the real `serve` bridge (its dispatch loop, worker pool, shared writer, JSON-RPC
//! framing) over an in-process pipe that models stdio: a still-open blocking reader and a writer that
//! TIMESTAMPS each response line as its bytes leave the bridge. A fake `agent.sock` models a daemon
//! whose background `Execute` runs stay in flight for the whole test and whose `Status` read is
//! SLOW/contended — the exact shape that made a `request_status(wait_ms=…)` sit for minutes. The
//! assertion is at the response boundary: the status response line must leave the bridge within its
//! advertised wait (+ the immediate-read floor + a small epsilon), never blocked by the two
//! concurrent background runs or by the slow daemon read.

use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use cermet_cli::mcp_bridge::server::{serve, AgentTransport};
use cermet_cli::mcp_bridge::{AgentCommand, AgentError};
use serde_json::{json, Value};

/// A blocking, still-open stdin: `read` parks until a line is pushed or the stream is closed (EOF),
/// so `serve` keeps running between requests exactly as it does against a live client pipe.
#[derive(Clone)]
struct PipeReader {
    inner: Arc<(Mutex<PipeState>, Condvar)>,
}
struct PipeState {
    buf: VecDeque<u8>,
    closed: bool,
}
impl PipeReader {
    fn new() -> Self {
        Self {
            inner: Arc::new((
                Mutex::new(PipeState {
                    buf: VecDeque::new(),
                    closed: false,
                }),
                Condvar::new(),
            )),
        }
    }
    fn push_line(&self, s: &str) {
        let (m, c) = &*self.inner;
        let mut g = m.lock().unwrap();
        g.buf.extend(s.as_bytes());
        g.buf.push_back(b'\n');
        c.notify_all();
    }
    fn close(&self) {
        let (m, c) = &*self.inner;
        m.lock().unwrap().closed = true;
        c.notify_all();
    }
}
impl Read for PipeReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let (m, c) = &*self.inner;
        let mut g = m.lock().unwrap();
        loop {
            if !g.buf.is_empty() {
                let n = out.len().min(g.buf.len());
                for slot in out.iter_mut().take(n) {
                    *slot = g.buf.pop_front().unwrap();
                }
                return Ok(n);
            }
            if g.closed {
                return Ok(0);
            }
            g = c.wait(g).unwrap();
        }
    }
}

/// A writer that timestamps each COMPLETE response line as the bridge writes it — the stdio response
/// boundary. `serve`'s writer task writes whole lines, so one `(Instant, line)` is one response.
#[derive(Clone)]
struct StampWriter {
    inner: Arc<Mutex<StampState>>,
}
struct StampState {
    pending: Vec<u8>,
    lines: Vec<(Instant, String)>,
}
impl StampWriter {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StampState {
                pending: Vec::new(),
                lines: Vec::new(),
            })),
        }
    }
    fn lines(&self) -> Vec<(Instant, String)> {
        self.inner.lock().unwrap().lines.clone()
    }
}
impl Write for StampWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let mut g = self.inner.lock().unwrap();
        g.pending.extend_from_slice(data);
        while let Some(pos) = g.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = g.pending.drain(..=pos).collect();
            let s = String::from_utf8_lossy(&line).trim().to_string();
            if !s.is_empty() {
                g.lines.push((Instant::now(), s));
            }
        }
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A daemon fake: `Execute` (a background run) stays in flight `run_secs`; `Status` is SLOW —
/// `call` blocks `status_secs` (a contended read), while `call_within` honors its clamp (times out
/// at the budget). Everything else answers instantly.
struct SlowDaemon {
    run: Duration,
    status: Duration,
}
impl SlowDaemon {
    fn status_frame() -> Value {
        json!({ "kind": "status", "request_id": "rq", "status": "running", "phase": "running" })
    }
    fn executed_frame() -> Value {
        json!({ "kind": "executed", "ok": true, "provider": "v", "action": "a", "result": {} })
    }
}
impl AgentTransport for SlowDaemon {
    fn call(&self, cmd: &AgentCommand) -> Result<Value, AgentError> {
        match cmd {
            AgentCommand::Execute { .. } => {
                std::thread::sleep(self.run);
                Ok(Self::executed_frame())
            }
            AgentCommand::Status { .. } => {
                std::thread::sleep(self.status);
                Ok(Self::status_frame())
            }
            _ => Ok(Self::status_frame()),
        }
    }
    fn call_within(&self, cmd: &AgentCommand, budget: Duration) -> Result<Value, AgentError> {
        // Model a real socket read clamped to `budget`: a daemon slower than the budget TIMES OUT
        // at the budget (fail closed) rather than running to completion.
        match cmd {
            AgentCommand::Status { .. } if self.status > budget => {
                std::thread::sleep(budget);
                Err(AgentError::Transport("read timed out".into()))
            }
            other => self.call(other),
        }
    }
}

fn exec_line(id: u64, request_id: &str, wait_ms: u64) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": { "name": "execute_capability",
                    "arguments": { "request_id": request_id, "wait_ms": wait_ms } }
    })
    .to_string()
}

fn status_line(id: u64, request_id: &str, wait_ms: u64) -> String {
    json!({
        "jsonrpc": "2.0", "id": id, "method": "tools/call",
        "params": { "name": "request_status",
                    "arguments": { "request_id": request_id, "wait_ms": wait_ms } }
    })
    .to_string()
}

/// Find the arrival Instant of the response line carrying `"id":<id>`.
fn arrival(lines: &[(Instant, String)], id: u64) -> Option<Instant> {
    let needle = format!("\"id\":{id}");
    lines
        .iter()
        .find(|(_, l)| l.contains(&needle))
        .map(|(t, _)| *t)
}

#[test]
fn bounded_status_leaves_the_bridge_on_time_with_two_background_runs() {
    let reader = PipeReader::new();
    let writer = StampWriter::new();
    let daemon = SlowDaemon {
        run: Duration::from_secs(4), // background runs stay in flight through the test
        status: Duration::from_secs(10), // a contended status read — the field failure shape
    };

    let srv_reader = reader.clone();
    let srv_writer = writer.clone();
    let server = std::thread::spawn(move || {
        serve(daemon, io::BufReader::new(srv_reader), srv_writer).expect("serve ok");
    });

    // Two background runs (wait_ms:0 → each returns a handle immediately and keeps running).
    reader.push_line(&exec_line(1, "rq-A", 0));
    reader.push_line(&exec_line(2, "rq-B", 0));
    // Give them a moment to enter their (blocking) Execute RPCs on the run pool.
    std::thread::sleep(Duration::from_millis(200));

    // Now a bounded status poll on a THIRD id, while both background runs are in flight and the
    // daemon read is slow. Its response must leave the bridge within the advertised wait + the
    // immediate-read floor (~3s) + epsilon — NEVER the 10s unbounded read.
    let pushed = Instant::now();
    reader.push_line(&status_line(3, "rq-C", 200));

    // Wait for the id:3 response line to appear at the writer.
    let deadline = pushed + Duration::from_secs(6);
    let mut status_at = None;
    while Instant::now() < deadline {
        if let Some(t) = arrival(&writer.lines(), 3) {
            status_at = Some(t);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let status_at = status_at.expect("the bounded status response must reach the stdio boundary");
    let took = status_at.duration_since(pushed);
    assert!(
        took < Duration::from_secs(5),
        "the status response left the bridge in {took:?} — bounded by call_within (immediate-read \
         floor ~3s); an unbounded read would have taken ~10s"
    );

    // The two background-run handles were answered promptly too (never blocked behind the status).
    let lines = writer.lines();
    assert!(
        arrival(&lines, 1).is_some(),
        "background run A got its handle"
    );
    assert!(
        arrival(&lines, 2).is_some(),
        "background run B got its handle"
    );

    reader.close();
    server.join().unwrap();
}
