//! The human-terminal seam shared by `connect` / `open` / `mcp install`: prompting, yes/no confirms,
//! opening a URL in the browser, and — the security-bearing one — capturing a provider token WITHOUT
//! echoing it. Everything side-effecting sits behind [`Terminal`] so the command logic is unit- and
//! integration-testable with the public [`ScriptedTerminal`] double (mirrors `presence::FixedPresence`).
//!
//! Secret hygiene: [`Terminal::read_secret`] returns a [`SecretString`] (redacted `Debug`, zeroized on
//! drop) and the real implementation turns OFF terminal echo for the duration of the read, so the
//! token never lands in scrollback.
//! FAIL CLOSED: if echo suppression cannot be ESTABLISHED on an interactive terminal, the
//! prompt is refused — the token must never silently echo. The termios calls sit behind the
//! [`Termios`] seam so tests can force that failure.

use secrecy::SecretString;

use crate::CliError;

/// A yes/no answer plus the interaction primitives the interactive CLI commands need.
pub trait Terminal {
    /// True when stdin is a TTY (an interactive human is present). Gates every prompt: a
    /// non-interactive run never blocks on a confirm and falls back to its fail-closed default.
    fn is_interactive(&self) -> bool;
    /// Ask a yes/no question, returning the human's answer (or `default` when they just hit enter).
    fn confirm(&self, prompt: &str, default: bool) -> bool;
    /// Open a URL in the browser (best-effort; failures are swallowed).
    fn launch(&self, url: &str);
    /// Capture a secret from the human WITHOUT echoing it (interactive) or read one line from stdin
    /// (piped). The value is wrapped immediately; it is never returned as a plain `String`.
    ///
    /// FAIL CLOSED: on an interactive terminal where echo cannot be disabled, this returns `Err`
    /// and reads NOTHING — a degraded echoing prompt is never offered.
    fn read_secret(&self, prompt: &str) -> Result<SecretString, CliError>;
}

/// The termios seam: get/set the stdin terminal attributes. Injectable so a test can force
/// the suppression failure paths (`tcgetattr`/`tcsetattr` errors) that a real TTY won't produce.
pub trait Termios {
    fn get(&self) -> std::io::Result<libc::termios>;
    fn set(&self, t: &libc::termios) -> std::io::Result<()>;
}

/// The real stdin termios.
pub struct StdTermios;

impl Termios for StdTermios {
    fn get(&self) -> std::io::Result<libc::termios> {
        // SAFETY: tcgetattr writes into the zeroed struct; errors surface via the return code.
        unsafe {
            let mut t: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(t)
        }
    }
    fn set(&self, t: &libc::termios) -> std::io::Result<()> {
        // SAFETY: tcsetattr reads the caller's struct; errors surface via the return code.
        unsafe {
            if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
    }
}

/// Read one secret line with echo PROVABLY off: establish suppression first — refusing the
/// prompt entirely when it cannot be established — then read, then restore. `read_line` is the input
/// seam (stdin in production). On `Err`, nothing was read.
fn read_secret_no_echo(
    ops: &dyn Termios,
    prompt: &str,
    read_line: &mut dyn FnMut() -> std::io::Result<String>,
) -> Result<SecretString, CliError> {
    use std::io::Write;
    // Suppression is established BEFORE anything is read. If it cannot be, the prompt is
    // refused outright — never a degraded read with echo possibly on.
    let guard = EchoGuard::disable(ops).map_err(|e| {
        CliError::Refused(format!(
            "refusing the {prompt} prompt: terminal echo could not be disabled ({e}), so typing \
             the token would echo it into your scrollback. Pipe the token on stdin instead \
             (e.g. `... < token-file`)."
        ))
    })?;
    eprint!("{prompt}: ");
    let _ = std::io::stderr().flush();
    let line = read_line().map_err(|e| {
        CliError::Refused(format!("could not read the token from the terminal: {e}"))
    })?;
    drop(guard); // restore echo before the trailing newline
    eprintln!();
    Ok(SecretString::new(line.trim().to_string()))
}

/// The real terminal: stdin/stdout with termios echo-suppression for the secret read.
pub struct StdTerminal;

impl Terminal for StdTerminal {
    fn is_interactive(&self) -> bool {
        // SAFETY: isatty on fd 0 is a pure query with no memory effects.
        unsafe { libc::isatty(libc::STDIN_FILENO) == 1 }
    }

    fn confirm(&self, prompt: &str, default: bool) -> bool {
        use std::io::Write;
        let hint = if default { "[Y/n]" } else { "[y/N]" };
        eprint!("{prompt} {hint}: ");
        let _ = std::io::stderr().flush();
        let mut line = String::new();
        if std::io::stdin().read_line(&mut line).is_err() {
            return default;
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "" => default,
            "y" | "yes" => true,
            "n" | "no" => false,
            _ => default,
        }
    }

    fn launch(&self, url: &str) {
        // Best-effort, detached — a browser failure must never fail the command.
        #[cfg(target_os = "macos")]
        let opener = "open";
        #[cfg(not(target_os = "macos"))]
        let opener = "xdg-open";
        let _ = std::process::Command::new(opener)
            .arg(url)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }

    fn read_secret(&self, prompt: &str) -> Result<SecretString, CliError> {
        if self.is_interactive() {
            read_secret_no_echo(&StdTermios, prompt, &mut || {
                let mut line = String::new();
                std::io::stdin().read_line(&mut line)?;
                Ok(line)
            })
        } else {
            // Piped input: nothing echoes (there is no terminal), so no suppression is needed.
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            Ok(SecretString::new(line.trim().to_string()))
        }
    }
}

/// RAII echo suppression over the [`Termios`] seam: clear the ECHO flag, restore the saved attrs on
/// drop. A guard EXISTS only when suppression actually succeeded: `disable` fails closed on
/// a `tcgetattr`/`tcsetattr` error, and `saved` is recorded only after the suppressing set SUCCEEDED,
/// so drop can never "restore" attributes that were never changed.
struct EchoGuard<'a> {
    ops: &'a dyn Termios,
    saved: libc::termios,
}

impl<'a> EchoGuard<'a> {
    /// Establish echo suppression or fail closed. The caller must treat `Err` as "the
    /// prompt cannot be offered safely" and refuse to read.
    fn disable(ops: &'a dyn Termios) -> Result<Self, String> {
        let saved = ops.get().map_err(|e| format!("tcgetattr failed: {e}"))?;
        let mut off = saved;
        off.c_lflag &= !libc::ECHO;
        ops.set(&off)
            .map_err(|e| format!("tcsetattr failed: {e}"))?;
        Ok(Self { ops, saved })
    }
}

impl Drop for EchoGuard<'_> {
    fn drop(&mut self) {
        // Best-effort restore: if it fails, echo STAYS OFF — the safe direction for a secret.
        let _ = self.ops.set(&self.saved);
    }
}

/// A public test double: pre-scripted confirm answers + a fixed secret, recording launched URLs. Used
/// by the connect/open/mcp integration tests (the analog of `presence::FixedPresence`).
pub struct ScriptedTerminal {
    pub interactive: bool,
    /// Answers handed out FIFO on each `confirm`; when exhausted the call returns `default`.
    pub confirms: std::sync::Mutex<std::collections::VecDeque<bool>>,
    /// The secret `read_secret` returns (obviously-fake in tests — never a real token).
    pub secret: SecretString,
    pub launched: std::sync::Mutex<Vec<String>>,
    /// Every prompt `confirm` was asked, in order. A ceremony's review text is the thing a human
    /// actually accepts, so a test that only checks the ANSWER checks the wrong half; recording the
    /// question lets the suite assert what was on screen when it was answered.
    pub prompts: std::sync::Mutex<Vec<String>>,
}

impl ScriptedTerminal {
    pub fn new(interactive: bool, secret: &str, confirms: Vec<bool>) -> Self {
        Self {
            interactive,
            confirms: std::sync::Mutex::new(confirms.into_iter().collect()),
            secret: SecretString::new(secret.to_string()),
            launched: std::sync::Mutex::new(Vec::new()),
            prompts: std::sync::Mutex::new(Vec::new()),
        }
    }
}

impl Terminal for ScriptedTerminal {
    fn is_interactive(&self) -> bool {
        self.interactive
    }
    fn confirm(&self, prompt: &str, default: bool) -> bool {
        self.prompts.lock().unwrap().push(prompt.to_string());
        self.confirms.lock().unwrap().pop_front().unwrap_or(default)
    }
    fn launch(&self, url: &str) {
        self.launched.lock().unwrap().push(url.to_string());
    }
    fn read_secret(&self, _prompt: &str) -> Result<SecretString, CliError> {
        Ok(self.secret.clone())
    }
}

#[cfg(test)]
// `tcflag_t as u64` is same-type on macOS (c_ulong) but a REAL widening on Linux (u32) — the casts
// are portability, not noise.
#[allow(clippy::unnecessary_cast)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use std::cell::RefCell;

    /// A scripted termios: optionally failing get/set, recording every `set` c_lflag so the tests can
    /// prove ECHO was cleared then restored — and, on the failure paths, that NOTHING was set.
    struct FakeTermios {
        fail_get: bool,
        fail_set: bool,
        set_lflags: RefCell<Vec<u64>>,
    }

    impl FakeTermios {
        fn new(fail_get: bool, fail_set: bool) -> Self {
            Self {
                fail_get,
                fail_set,
                set_lflags: RefCell::new(Vec::new()),
            }
        }
    }

    impl Termios for FakeTermios {
        fn get(&self) -> std::io::Result<libc::termios> {
            if self.fail_get {
                return Err(std::io::Error::other("tcgetattr failed"));
            }
            // SAFETY: an all-zero termios is a valid value object for the test.
            let mut t: libc::termios = unsafe { std::mem::zeroed() };
            t.c_lflag = libc::ECHO | libc::ICANON;
            Ok(t)
        }
        fn set(&self, t: &libc::termios) -> std::io::Result<()> {
            if self.fail_set {
                return Err(std::io::Error::other("tcsetattr failed"));
            }
            self.set_lflags.borrow_mut().push(t.c_lflag as u64);
            Ok(())
        }
    }

    fn never_reads() -> (RefCell<bool>, impl FnMut() -> std::io::Result<String>) {
        let called = RefCell::new(false);
        (called, || {
            panic!("the reader must NEVER run when echo suppression failed")
        })
    }

    // ---- echo suppression failure must REFUSE the prompt, never read with echo on ---------------

    #[test]
    fn tcgetattr_failure_refuses_the_prompt_and_reads_nothing() {
        let ops = FakeTermios::new(true, false);
        let (_flag, mut reader) = never_reads();
        let err = read_secret_no_echo(&ops, "token", &mut reader)
            .expect_err("a failed tcgetattr must refuse the prompt");
        assert!(matches!(err, CliError::Refused(_)), "{err:?}");
        let msg = format!("{err}");
        assert!(
            msg.contains("echo"),
            "the refusal must tell the operator WHY (echo could not be disabled): {msg}"
        );
        assert!(
            ops.set_lflags.borrow().is_empty(),
            "nothing may be set after a failed get"
        );
    }

    #[test]
    fn tcsetattr_failure_refuses_the_prompt_and_never_restores() {
        let ops = FakeTermios::new(false, true);
        let (_flag, mut reader) = never_reads();
        let err = read_secret_no_echo(&ops, "token", &mut reader)
            .expect_err("a failed tcsetattr must refuse the prompt");
        assert!(matches!(err, CliError::Refused(_)), "{err:?}");
        // `saved` is set only after a SUCCESSFUL tcsetattr — the drop must not "restore" attrs that
        // were never changed (set is not called again after the failure).
        assert!(
            ops.set_lflags.borrow().is_empty(),
            "no successful set may be recorded, and no restore may follow a failed suppression"
        );
    }

    #[test]
    fn successful_suppression_clears_echo_reads_then_restores() {
        let ops = FakeTermios::new(false, false);
        let mut reader = || Ok("  tok_FAKE_123  \n".to_string());
        let secret = read_secret_no_echo(&ops, "token", &mut reader).expect("suppressed read ok");
        assert_eq!(secret.expose_secret(), "tok_FAKE_123", "trimmed");
        let sets = ops.set_lflags.borrow();
        assert_eq!(sets.len(), 2, "one suppress + one restore: {sets:?}");
        assert_eq!(
            sets[0] & libc::ECHO as u64,
            0,
            "the first set must have ECHO cleared"
        );
        assert_ne!(
            sets[1] & libc::ECHO as u64,
            0,
            "the restore must bring the ORIGINAL (echoing) attrs back"
        );
    }
}
