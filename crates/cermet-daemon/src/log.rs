//! Non-blocking, drop-on-full daemon logging.
//!
//! The `agent.sock` serve loop must NEVER block on stderr backpressure: a stalled stderr reader
//! (a pipe or journal whose consumer hangs) would otherwise pin a connection slot far past the
//! response budget. So the hot path only `try_send`s a bounded line to a background
//! writer thread that owns stderr — if the queue is full (or the writer/stderr stalls), the line
//! is DROPPED, never queued-blocking. Per-request content (e.g. an attacker-guessed grant id,
//! bounded only by the 64 KiB inbound frame) is truncated and stripped of control chars first.

use std::sync::mpsc::{sync_channel, SyncSender, TrySendError};
use std::sync::OnceLock;

/// Max queued lines before new ones are dropped (bounds memory; the producer never blocks).
const LOG_QUEUE: usize = 256;
/// Max characters kept per line — caps attacker-influenceable content and prevents log-line injection.
const MAX_LINE: usize = 256;

/// A non-blocking sink: `emit` queues a line or drops it, but NEVER blocks the caller.
#[derive(Clone)]
pub struct Logger {
    tx: SyncSender<String>,
}

impl Logger {
    /// Spawn the background stderr writer and return a sink for it. The writer thread owns stderr,
    /// so if stderr stalls only that one thread blocks — never a serve-loop handler.
    pub fn spawn_stderr() -> Logger {
        let (tx, rx) = sync_channel::<String>(LOG_QUEUE);
        std::thread::spawn(move || {
            use std::io::Write;
            let mut err = std::io::stderr();
            for line in rx {
                let _ = writeln!(err, "{line}");
            }
        });
        Logger { tx }
    }

    /// Queue one line, or DROP it if the queue is full or the writer is gone. Never blocks.
    pub fn emit(&self, msg: impl Into<String>) {
        let mut line = msg.into();
        sanitize(&mut line);
        match self.tx.try_send(line) {
            Ok(()) | Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

/// Bound the line length and neutralize control chars (so a crafted grant id cannot inject a
/// newline-delimited fake log line, nor bloat the bounded queue).
fn sanitize(line: &mut String) {
    if line.chars().any(char::is_control) {
        *line = line
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect();
    }
    if line.chars().count() > MAX_LINE {
        *line = line.chars().take(MAX_LINE).collect();
        line.push('…');
    }
}

static SINK: OnceLock<Logger> = OnceLock::new();

/// Install the process-wide stderr logger once, at daemon startup. Idempotent.
pub fn init_stderr() {
    let _ = SINK.set(Logger::spawn_stderr());
}

/// Emit through the process-wide logger, or DROP if logging was never initialized (e.g. tests).
/// NEVER blocks — the serve loop calls this on the hot path.
pub fn emit(msg: impl Into<String>) {
    if let Some(sink) = SINK.get() {
        sink.emit(msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn emit_never_blocks_even_when_the_queue_is_full_or_gone() {
        // A consumer that is alive but NEVER reads: the queue fills and every later try_send returns
        // Full -> drop. If `emit` blocked, this loop would hang far past the timeout.
        let (tx, _rx_held) = sync_channel::<String>(4);
        let logger = Logger { tx };
        let start = Instant::now();
        for i in 0..100_000 {
            logger.emit(format!("execute failed: grant {i}"));
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "emit must never block (drop-on-full), even far past the queue capacity: {:?}",
            start.elapsed()
        );
        // Receiver gone -> Disconnected -> drop, still no block.
        drop(_rx_held);
        logger.emit("after the receiver is gone");
    }

    #[test]
    fn sanitize_bounds_length_and_strips_control_chars() {
        let mut long = format!("grant {}", "A".repeat(10_000));
        sanitize(&mut long);
        assert!(
            long.chars().count() <= MAX_LINE + 1,
            "a long line is truncated to the cap (+ the ellipsis)"
        );

        let mut injected = "ok\nFAKE LOG LINE\r\nmore".to_string();
        sanitize(&mut injected);
        assert!(
            !injected.contains('\n') && !injected.contains('\r'),
            "control chars are neutralized so a crafted id cannot inject log lines: {injected:?}"
        );
    }
}
