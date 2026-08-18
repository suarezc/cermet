//! Hardened Linux PAM password re-auth presence gate (`PamPasswordPresence`).
//!
//! On the Linux operator path there is no Touch-ID; the human-only mutation gate is instead a
//! **live password re-authentication of the invoking approver** against a dedicated PAM service
//! (`/etc/pam.d/cermet`). A `Confirmed` outcome means: a real human, sitting at the controlling
//! TTY, typed the OS account password for the euid that is running the CLI, and PAM accepted it.
//!
//! ## Threat model (why every step below exists)
//! The adversary is a compromised/misconfigured host or a stray automation trying to slip an
//! approval past the human gate. The defenses are scoped to that:
//!   * A PAM service that is missing/attacker-writable would let the request fall through to PAM's
//!     permissive `other` stack (often `pam_permit`) → we `stat` and refuse anything not a
//!     root-owned, non-group/other-writable regular file (step 1).
//!   * A non-interactive context (cron, pipe, daemon) can never satisfy a live-human gate → we
//!     require a controlling TTY up front (step 2).
//!   * A PAM-side username we did not choose could re-target the auth at a different (weaker)
//!     account → we derive `PAM_USER` from `geteuid()` ourselves and re-check it did not change
//!     under us (steps 3 & 8).
//!   * A permissive/cached module that returns `PAM_SUCCESS` **without ever prompting** would be a
//!     silent bypass → we count real echo-off prompts and reject a success with zero (steps 5 & 7).
//!
//! ## No link-time PAM dependency
//! The daemon must never link PAM; only this client uses it, and the dev symlink `libpam.so` is
//! absent in our environment (only the runtime `libpam.so.0` exists). So PAM is loaded at RUNTIME
//! via `dlopen("libpam.so.0")` + `dlsym` — there is no `#[link(name="pam")]` and no `pam` crate.
//! `dlopen`/`dlsym`/`pam_start` failures are **mechanism-absent** and map to `Unavailable`, never
//! `Denied`: a missing mechanism must not read as a human saying "no".

// ---------------------------------------------------------------------------------------------
// Non-Linux stub: keep the type name total on every platform (the CLII references it under cfg).
// ---------------------------------------------------------------------------------------------

/// PAM password re-auth presence gate. On non-Linux hosts this is a stub that is always
/// `Unavailable` (PAM is Linux-only); the real implementation lives under `cfg(target_os = "linux")`.
#[cfg(not(target_os = "linux"))]
pub struct PamPasswordPresence;

#[cfg(not(target_os = "linux"))]
impl crate::presence::Presence for PamPasswordPresence {
    fn confirm(&self, _reason: &str) -> crate::presence::PresenceOutcome {
        crate::presence::PresenceOutcome::Unavailable("PAM presence is Linux-only".into())
    }
}

// ---------------------------------------------------------------------------------------------
// Linux: the real hardened implementation.
// ---------------------------------------------------------------------------------------------

/// PAM password re-auth presence gate for the Linux operator path.
#[cfg(target_os = "linux")]
pub struct PamPasswordPresence;

#[cfg(target_os = "linux")]
impl crate::presence::Presence for PamPasswordPresence {
    fn confirm(&self, reason: &str) -> crate::presence::PresenceOutcome {
        linux::confirm(reason)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{CStr, CString};
    use std::io::Write;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;
    use std::path::Path;
    use std::ptr;

    use libc::{c_char, c_int, c_void};
    use zeroize::Zeroizing;

    use crate::presence::PresenceOutcome;

    /// The dedicated PAM service name and its config path. A *dedicated* service (not `login` or
    /// `sudo`) means our precondition check governs exactly the stack that authenticates approvals.
    const SERVICE_NAME: &str = "cermet";
    const SERVICE_FILE_PATH: &str = "/etc/pam.d/cermet";

    /// Cap the password read so a pathological/hostile TTY cannot make us allocate unboundedly, and
    /// so the zeroizing buffer never reallocates (which would leak plaintext into freed pages).
    const MAX_PASSWORD_LEN: usize = 1024;

    // --- PAM constants (Linux-PAM ABI) --------------------------------------------------------
    const PAM_SUCCESS: c_int = 0;
    const PAM_PROMPT_ECHO_OFF: c_int = 1;
    const PAM_PROMPT_ECHO_ON: c_int = 2;
    const PAM_ERROR_MSG: c_int = 3;
    const PAM_TEXT_INFO: c_int = 4;
    const PAM_USER: c_int = 2;
    const PAM_CONV_ERR: c_int = 19;

    // --- PAM ABI structs (repr(C)) ------------------------------------------------------------

    /// Opaque PAM handle; we never dereference it, only pass the pointer back to PAM.
    enum PamHandle {}

    #[repr(C)]
    struct PamMessage {
        msg_style: c_int,
        msg: *const c_char,
    }

    #[repr(C)]
    struct PamResponse {
        resp: *mut c_char,
        resp_retcode: c_int,
    }

    /// The conversation callback signature. On Linux-PAM `msg` is an array of POINTERS to
    /// `pam_message` (`*const *const PamMessage`); `resp` is where we store our malloc'd response
    /// array for PAM to consume and free.
    type ConvFn = extern "C" fn(
        num_msg: c_int,
        msg: *const *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata: *mut c_void,
    ) -> c_int;

    #[repr(C)]
    struct PamConv {
        conv: Option<ConvFn>,
        appdata_ptr: *mut c_void,
    }

    // --- Runtime-resolved PAM entry points ----------------------------------------------------

    type PamStartFn = unsafe extern "C" fn(
        *const c_char,
        *const c_char,
        *const PamConv,
        *mut *mut PamHandle,
    ) -> c_int;
    type PamAuthenticateFn = unsafe extern "C" fn(*mut PamHandle, c_int) -> c_int;
    type PamAcctMgmtFn = unsafe extern "C" fn(*mut PamHandle, c_int) -> c_int;
    type PamEndFn = unsafe extern "C" fn(*mut PamHandle, c_int) -> c_int;
    type PamGetItemFn = unsafe extern "C" fn(*mut PamHandle, c_int, *mut *const c_void) -> c_int;

    struct Pam {
        start: PamStartFn,
        authenticate: PamAuthenticateFn,
        acct_mgmt: PamAcctMgmtFn,
        end: PamEndFn,
        get_item: PamGetItemFn,
    }

    impl Pam {
        /// `dlopen("libpam.so.0")` + `dlsym` the entry points we use. All failures here are
        /// mechanism-absent (→ `Unavailable`). We intentionally never `dlclose`: without a matching
        /// close the library stays mapped for the process lifetime, keeping our symbols valid; this
        /// is a short-lived interactive CLI, not a hot loop, so the retained mapping is fine.
        fn load() -> Result<Pam, String> {
            unsafe {
                let handle =
                    libc::dlopen(b"libpam.so.0\0".as_ptr() as *const c_char, libc::RTLD_NOW);
                if handle.is_null() {
                    return Err("libpam.so.0 could not be loaded; PAM presence unavailable".into());
                }
                Ok(Pam {
                    start: std::mem::transmute::<*mut c_void, PamStartFn>(dlsym_req(
                        handle,
                        b"pam_start\0",
                    )?),
                    authenticate: std::mem::transmute::<*mut c_void, PamAuthenticateFn>(dlsym_req(
                        handle,
                        b"pam_authenticate\0",
                    )?),
                    acct_mgmt: std::mem::transmute::<*mut c_void, PamAcctMgmtFn>(dlsym_req(
                        handle,
                        b"pam_acct_mgmt\0",
                    )?),
                    end: std::mem::transmute::<*mut c_void, PamEndFn>(dlsym_req(
                        handle,
                        b"pam_end\0",
                    )?),
                    get_item: std::mem::transmute::<*mut c_void, PamGetItemFn>(dlsym_req(
                        handle,
                        b"pam_get_item\0",
                    )?),
                })
            }
        }
    }

    /// `dlsym` a required symbol; a missing symbol means the loaded library is not the PAM we expect.
    unsafe fn dlsym_req(handle: *mut c_void, name: &[u8]) -> Result<*mut c_void, String> {
        let p = libc::dlsym(handle, name.as_ptr() as *const c_char);
        if p.is_null() {
            let pretty = String::from_utf8_lossy(&name[..name.len().saturating_sub(1)]);
            Err(format!(
                "PAM symbol `{pretty}` missing; PAM presence unavailable"
            ))
        } else {
            Ok(p)
        }
    }

    // --- Step 1: service-file precondition ----------------------------------------------------

    /// Pure decision for the service-file metadata, factored out so every branch (including the
    /// root-owned Ok path we cannot create as a non-root test) is unit-testable.
    fn evaluate_service_meta(
        is_file: bool,
        uid: u32,
        mode: u32,
        path_display: &str,
    ) -> Result<(), String> {
        if !is_file {
            return Err(format!(
                "PAM service file {path_display} is not a regular file"
            ));
        }
        // Not root-owned → an unprivileged user could edit the auth stack to `pam_permit`.
        if uid != 0 {
            return Err(format!(
                "PAM service file {path_display} is not owned by root"
            ));
        }
        // Any group/other write bit → same edit-the-stack risk from a non-owner.
        if mode & 0o022 != 0 {
            return Err(format!(
                "PAM service file {path_display} is group- or world-writable"
            ));
        }
        // The dedicated stack must be readable by the unprivileged invoking client. Requiring the
        // root-owned service file to be world-readable is the deterministic packaging contract
        // (0644); accepting 0600/0640 can make Linux-PAM silently fall through to `/etc/pam.d/other`.
        if mode & 0o004 == 0 {
            return Err(format!(
                "PAM service file {path_display} is not readable by the invoking client"
            ));
        }
        Ok(())
    }

    /// `lstat` the service file and apply [`evaluate_service_meta`]. We use `symlink_metadata`
    /// (lstat, not stat) deliberately: a symlink at this path is treated as "not a regular file"
    /// and refused, so an attacker cannot swap in a symlink to a stack they control. This refusal
    /// is what keeps the PAM `other` fallback stack from ever being reached.
    fn service_file_ok(path: &Path) -> Result<(), String> {
        let md = std::fs::symlink_metadata(path).map_err(|_| {
            format!(
                "PAM service file {} is absent or unreadable",
                path.display()
            )
        })?;
        evaluate_service_meta(
            md.is_file(),
            md.uid(),
            md.mode(),
            &path.display().to_string(),
        )?;
        // Prove the current process can actually open the explicit stack before pam_start. This is
        // intentionally redundant with the 0644 contract above: ACLs or other filesystem policy can
        // still deny an apparently-readable mode, and that must fail closed before PAM sees a name.
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map(|_| ())
            .map_err(|_| {
                format!(
                    "PAM service file {} is unreadable by this client",
                    path.display()
                )
            })
    }

    // --- Step 10: pure final-decision helper --------------------------------------------------

    /// The final gate. `Confirmed` requires ALL of: authenticate succeeded, account management
    /// succeeded, at least one real echo-off password prompt actually occurred, and `PAM_USER` was
    /// unchanged. Anything else is `Denied` — including a "success" with zero prompts (a permissive
    /// or cached module) and a `PAM_USER` the stack silently re-targeted. Mechanism-absent failures
    /// never reach here; they short-circuit to `Unavailable`.
    fn decide(
        auth_rc: i32,
        acct_rc: i32,
        echo_off_prompts: usize,
        user_ok: bool,
    ) -> PresenceOutcome {
        if auth_rc == PAM_SUCCESS && acct_rc == PAM_SUCCESS && echo_off_prompts >= 1 && user_ok {
            PresenceOutcome::Confirmed
        } else {
            PresenceOutcome::Denied
        }
    }

    // --- Step 5: conversation callback + TTY password read ------------------------------------

    /// State passed to the conversation callback via `appdata`, so we can count the real challenges.
    struct ConvState {
        echo_off_prompts: usize,
    }

    /// Restores the TTY's original termios on drop — ECHO is re-enabled no matter how we leave the
    /// read (normal return, early error, or panic caught above the FFI boundary).
    struct TermiosGuard {
        fd: c_int,
        orig: libc::termios,
    }

    impl Drop for TermiosGuard {
        fn drop(&mut self) {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig);
            }
        }
    }

    /// Read bytes through the same fd loop used for `/dev/tty`. Split from the termios setup so the
    /// conversation can be regression-tested against real `read(2)` error/EOF outcomes.
    fn read_tty_line_from_fd(fd: c_int) -> Result<Zeroizing<Vec<u8>>, ()> {
        let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(MAX_PASSWORD_LEN + 1));
        let mut byte = [0u8; 1];
        loop {
            let n = unsafe { libc::read(fd, byte.as_mut_ptr() as *mut c_void, 1) };
            if n < 0 {
                return Err(());
            }
            if n == 0 {
                return Err(()); // EOF before Enter is an incomplete response.
            }
            if byte[0] == b'\n' {
                break;
            }
            if buf.len() >= MAX_PASSWORD_LEN {
                return Err(());
            }
            buf.push(byte[0]);
        }
        Ok(buf)
    }

    /// Read one line from `/dev/tty`. With `echo == false` (password) the terminal's ECHO flag is
    /// cleared for the duration of the read and always restored by [`TermiosGuard`]. The returned
    /// buffer is [`Zeroizing`] and pre-sized so it never reallocates (no plaintext left in freed
    /// pages); it zeroizes on drop.
    fn read_tty_line(echo: bool) -> Result<Zeroizing<Vec<u8>>, ()> {
        let tty = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| ())?;
        let fd = tty.as_raw_fd();

        let mut orig: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
            return Err(());
        }
        let _guard = TermiosGuard { fd, orig };

        if !echo {
            let mut raw = orig;
            raw.c_lflag &= !libc::ECHO;
            if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) } != 0 {
                return Err(());
            }
        }

        let buf = read_tty_line_from_fd(fd)?;

        // With ECHO off, the user's Enter was not echoed; emit a newline so the terminal advances.
        if !echo {
            eprintln!();
        }
        Ok(buf)
    }

    /// `strdup` `buf` into a `malloc`'d, NUL-terminated C buffer for PAM to own and free. The caller
    /// still holds the zeroizing Rust copy and drops (zeroizes) it right after.
    unsafe fn strdup_for_pam(buf: &[u8]) -> Option<*mut c_char> {
        let len = buf.len();
        let p = libc::malloc(len + 1) as *mut u8;
        if p.is_null() {
            return None;
        }
        ptr::copy_nonoverlapping(buf.as_ptr(), p, len);
        *p.add(len) = 0;
        Some(p as *mut c_char)
    }

    /// Fill ONE prompt response: read the line, `strdup` it into the slot, and — only AFTER the
    /// response is actually stored — bump the completed echo-off counter. A tty-read or
    /// `strdup` failure leaves the counter untouched, so a caller whose `isatty(stdin)` passes but who
    /// has no controlling `/dev/tty` (open fails → `PAM_CONV_ERR`) can never leave a phantom
    /// "completed" challenge that `decide()` would read as `echo_off_prompts >= 1`.
    unsafe fn fill_prompt_response<F>(
        slot: &mut PamResponse,
        state: &mut ConvState,
        echo_off: bool,
        read: F,
    ) -> Result<(), ()>
    where
        F: FnOnce() -> Result<Zeroizing<Vec<u8>>, ()>,
    {
        let line = read()?;
        let p = strdup_for_pam(&line).ok_or(())?;
        slot.resp = p; // `line` (zeroizing) drops right after this.
        if echo_off {
            state.echo_off_prompts += 1;
        }
        Ok(())
    }

    /// Free a partially-filled response array on an error path (PAM only frees it on success).
    /// Zeroize each response string first — these are password copies.
    unsafe fn free_responses(arr: *mut PamResponse, filled: usize) {
        for i in 0..filled {
            let slot = &mut *arr.add(i);
            if !slot.resp.is_null() {
                let len = libc::strlen(slot.resp);
                ptr::write_bytes(slot.resp as *mut u8, 0, len);
                libc::free(slot.resp as *mut c_void);
                slot.resp = ptr::null_mut();
            }
        }
        libc::free(arr as *mut c_void);
    }

    /// Print a NUL-terminated C string to stderr (best-effort; used for prompts/messages).
    unsafe fn emit(msg: *const c_char, newline: bool) {
        if msg.is_null() {
            return;
        }
        let s = CStr::from_ptr(msg).to_string_lossy();
        if s.is_empty() {
            return;
        }
        if newline {
            eprintln!("{s}");
        } else {
            eprint!("{s}");
            let _ = std::io::stderr().flush();
        }
    }

    /// The PAM conversation callback. It must NOT unwind across the C boundary, so its body runs
    /// inside `catch_unwind`; a panic or any read failure returns `PAM_CONV_ERR`.
    extern "C" fn pam_conv_cb(
        num_msg: c_int,
        msg: *const *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata: *mut c_void,
    ) -> c_int {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| unsafe {
            conv_inner(num_msg, msg, resp, appdata)
        }));
        outcome.unwrap_or(PAM_CONV_ERR)
    }

    unsafe fn conv_inner(
        num_msg: c_int,
        msg: *const *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata: *mut c_void,
    ) -> c_int {
        conv_inner_with_reader(num_msg, msg, resp, appdata, read_tty_line)
    }

    unsafe fn conv_inner_with_reader<F>(
        num_msg: c_int,
        msg: *const *const PamMessage,
        resp: *mut *mut PamResponse,
        appdata: *mut c_void,
        mut read: F,
    ) -> c_int
    where
        F: FnMut(bool) -> Result<Zeroizing<Vec<u8>>, ()>,
    {
        if num_msg <= 0 || msg.is_null() || resp.is_null() || appdata.is_null() {
            return PAM_CONV_ERR;
        }
        let state = &mut *(appdata as *mut ConvState);
        let n = num_msg as usize;

        // PAM owns and frees this array on success (calloc → zeroed slots).
        let arr = libc::calloc(n, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        if arr.is_null() {
            return PAM_CONV_ERR;
        }

        for i in 0..n {
            let m_ptr = *msg.add(i);
            if m_ptr.is_null() {
                continue;
            }
            let m = &*m_ptr;
            let slot = &mut *arr.add(i);
            slot.resp_retcode = 0;

            match m.msg_style {
                PAM_PROMPT_ECHO_OFF => {
                    // The echo-off counter is bumped by `fill_prompt_response` ONLY after the response
                    // is stored — never on a tty-read/strdup failure.
                    emit(m.msg, false);
                    if fill_prompt_response(slot, state, true, || read(false)).is_err() {
                        free_responses(arr, i);
                        return PAM_CONV_ERR;
                    }
                }
                PAM_PROMPT_ECHO_ON => {
                    emit(m.msg, false);
                    if fill_prompt_response(slot, state, false, || read(true)).is_err() {
                        free_responses(arr, i);
                        return PAM_CONV_ERR;
                    }
                }
                PAM_ERROR_MSG | PAM_TEXT_INFO => {
                    emit(m.msg, true);
                    slot.resp = ptr::null_mut();
                }
                _ => {
                    slot.resp = ptr::null_mut();
                }
            }
        }

        *resp = arr;
        PAM_SUCCESS
    }

    // --- Step 8: verify PAM_USER unchanged ----------------------------------------------------

    /// After a successful auth, confirm the stack did not re-target `PAM_USER` away from the euid
    /// name we started with.
    unsafe fn pam_user_unchanged(pam: &Pam, handle: *mut PamHandle, expected: &str) -> bool {
        let mut item: *const c_void = ptr::null();
        let rc = (pam.get_item)(handle, PAM_USER, &mut item);
        if rc != PAM_SUCCESS || item.is_null() {
            return false;
        }
        match CStr::from_ptr(item as *const c_char).to_str() {
            Ok(got) => got == expected,
            Err(_) => false,
        }
    }

    // --- The orchestrated confirm() -----------------------------------------------------------

    pub(super) fn confirm(reason: &str) -> PresenceOutcome {
        // Step 1: the service file must be a trusted, root-owned, non-writable regular file.
        if let Err(e) = service_file_ok(Path::new(SERVICE_FILE_PATH)) {
            return PresenceOutcome::Unavailable(e);
        }

        // Step 2: a live-human gate is meaningless without an interactive controlling TTY.
        if unsafe { libc::isatty(libc::STDIN_FILENO) } == 0 {
            return PresenceOutcome::Unavailable(
                "PAM presence requires an interactive terminal (no controlling TTY)".into(),
            );
        }

        // Step 3: derive the username from the invoking euid — never trust a PAM-side name.
        let euid = nix::unistd::geteuid();
        let username = match nix::unistd::User::from_uid(euid) {
            Ok(Some(u)) => u.name,
            _ => {
                return PresenceOutcome::Unavailable(
                    "could not resolve the invoking user for PAM authentication".into(),
                )
            }
        };

        // Runtime-load PAM (mechanism-absent → Unavailable).
        let pam = match Pam::load() {
            Ok(p) => p,
            Err(e) => return PresenceOutcome::Unavailable(e),
        };

        let service_c = match CString::new(SERVICE_NAME) {
            Ok(c) => c,
            Err(_) => return PresenceOutcome::Unavailable("invalid PAM service name".into()),
        };
        let user_c = match CString::new(username.clone()) {
            Ok(c) => c,
            Err(_) => return PresenceOutcome::Unavailable("invalid PAM username".into()),
        };

        // Give the human context for what they are authorizing.
        eprintln!("cermet: password required to authorize: {reason}");

        // Step 5: conversation state (prompt counter) + callback.
        let mut state = ConvState {
            echo_off_prompts: 0,
        };
        let conv = PamConv {
            conv: Some(pam_conv_cb),
            appdata_ptr: &mut state as *mut ConvState as *mut c_void,
        };

        // Step 4: a fresh handle per call (no caching).
        let mut handle: *mut PamHandle = ptr::null_mut();
        let start_rc =
            unsafe { (pam.start)(service_c.as_ptr(), user_c.as_ptr(), &conv, &mut handle) };
        if start_rc != PAM_SUCCESS {
            // pam_start failed — mechanism problem, not a human "no".
            // Step 9: if a handle was nonetheless produced, end it.
            if !handle.is_null() {
                unsafe {
                    (pam.end)(handle, start_rc);
                }
            }
            return PresenceOutcome::Unavailable(format!(
                "pam_start failed for service `{SERVICE_NAME}` (rc={start_rc})"
            ));
        }
        if handle.is_null() {
            return PresenceOutcome::Unavailable("pam_start returned a null handle".into());
        }

        // Step 6: authenticate, then account management only if auth succeeded.
        let auth_rc = unsafe { (pam.authenticate)(handle, 0) };
        let (acct_rc, user_ok) = if auth_rc == PAM_SUCCESS {
            let acct = unsafe { (pam.acct_mgmt)(handle, 0) };
            let uok = unsafe { pam_user_unchanged(&pam, handle, &username) };
            (acct, uok)
        } else {
            // Sentinel non-success; decide() denies on auth_rc != 0 regardless.
            (-1, false)
        };

        // Steps 7, 8, 10: final decision (echo-off count + user check baked in).
        let outcome = decide(auth_rc, acct_rc, state.echo_off_prompts, user_ok);

        // Step 9: end the handle on every post-start path.
        unsafe {
            (pam.end)(handle, auth_rc);
        }

        outcome
    }

    // -----------------------------------------------------------------------------------------
    // Tests: FS-precondition + decide() only. A real pam_authenticate needs a configured stack and
    // a real password — that is exercised in a live rehearsal, not here.
    // -----------------------------------------------------------------------------------------
    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::{Seek, SeekFrom};
        use std::os::unix::fs::PermissionsExt;

        // evaluate_service_meta: the pure branch coverage (including the root-owned Ok path we can't
        // create as a non-root test).
        #[test]
        fn service_meta_accepts_root_owned_0644() {
            assert!(evaluate_service_meta(true, 0, 0o644, "/etc/pam.d/cermet").is_ok());
        }

        #[test]
        fn service_meta_rejects_root_owned_stack_unreadable_by_the_client() {
            for mode in [0o000, 0o400, 0o600, 0o640] {
                assert!(
                    evaluate_service_meta(true, 0, mode, "/etc/pam.d/cermet").is_err(),
                    "mode {mode:o} lets an unprivileged client fall through to PAM `other`"
                );
            }
        }

        #[test]
        fn service_meta_rejects_non_regular() {
            assert!(evaluate_service_meta(false, 0, 0o644, "/etc/pam.d/cermet").is_err());
        }

        #[test]
        fn service_meta_rejects_non_root() {
            assert!(evaluate_service_meta(true, 1000, 0o644, "/etc/pam.d/cermet").is_err());
        }

        #[test]
        fn service_meta_rejects_group_or_world_writable() {
            assert!(evaluate_service_meta(true, 0, 0o664, "/x").is_err()); // group write
            assert!(evaluate_service_meta(true, 0, 0o646, "/x").is_err()); // other write
            assert!(evaluate_service_meta(true, 0, 0o666, "/x").is_err()); // both
        }

        // service_file_ok: real filesystem paths (tests run as non-root).
        #[test]
        fn service_file_absent_errs() {
            assert!(service_file_ok(Path::new("/nonexistent/cermet/pam/service/file")).is_err());
        }

        #[test]
        fn service_file_non_root_temp_errs() {
            // A temp file we create is owned by us (uid != 0), so it must Err — this doubles as the
            // not-root-owned check.
            let f = tempfile::NamedTempFile::new().unwrap();
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(service_file_ok(f.path()).is_err());
        }

        #[test]
        fn service_file_world_writable_temp_errs() {
            let f = tempfile::NamedTempFile::new().unwrap();
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o666)).unwrap();
            assert!(service_file_ok(f.path()).is_err());
        }

        // The echo-off counter must move ONLY after the response is stored — a failed
        // tty-read/strdup must leave it at 0 so a phantom challenge can never satisfy decide().
        #[test]
        fn echo_off_counter_only_increments_after_response_is_stored() {
            let mut slot = PamResponse {
                resp: ptr::null_mut(),
                resp_retcode: 0,
            };
            let mut state = ConvState {
                echo_off_prompts: 0,
            };
            // Read FAILS (models isatty-passes-but-no-/dev/tty): counter untouched, slot untouched.
            let failed = unsafe { fill_prompt_response(&mut slot, &mut state, true, || Err(())) };
            assert!(failed.is_err());
            assert_eq!(
                state.echo_off_prompts, 0,
                "a failed tty read must NOT count a completed echo-off challenge"
            );
            assert!(slot.resp.is_null(), "no response stored on a failed read");

            // Read SUCCEEDS: counter moves to 1 and the response is stored (then freed).
            let ok = unsafe {
                fill_prompt_response(&mut slot, &mut state, true, || {
                    Ok(Zeroizing::new(b"pw".to_vec()))
                })
            };
            assert!(ok.is_ok());
            assert_eq!(
                state.echo_off_prompts, 1,
                "a stored response counts exactly one challenge"
            );
            assert!(!slot.resp.is_null());
            unsafe { libc::free(slot.resp as *mut c_void) };
        }

        #[test]
        fn tty_read_error_and_incomplete_eof_fail_the_real_conversation_seam() {
            fn assert_reader_failure(fd: c_int, case: &str) {
                let prompt = CString::new("Password: ").unwrap();
                let message = PamMessage {
                    msg_style: PAM_PROMPT_ECHO_OFF,
                    msg: prompt.as_ptr(),
                };
                let messages = [&message as *const PamMessage];
                let mut response: *mut PamResponse = ptr::null_mut();
                let mut state = ConvState {
                    echo_off_prompts: 0,
                };

                let rc = unsafe {
                    conv_inner_with_reader(
                        1,
                        messages.as_ptr(),
                        &mut response,
                        &mut state as *mut ConvState as *mut c_void,
                        |_| read_tty_line_from_fd(fd),
                    )
                };
                assert_eq!(rc, PAM_CONV_ERR, "{case} must fail the conversation");
                assert!(response.is_null(), "{case} must publish no PAM response");
                assert_eq!(
                    state.echo_off_prompts, 0,
                    "{case} must not count a completed echo-off prompt"
                );
            }

            let closed_fd = {
                let file = tempfile::tempfile().unwrap();
                file.as_raw_fd()
            };
            assert_reader_failure(closed_fd, "read error");

            let mut partial = tempfile::tempfile().unwrap();
            partial.write_all(b"partial password").unwrap();
            partial.seek(SeekFrom::Start(0)).unwrap();
            assert_reader_failure(partial.as_raw_fd(), "EOF before newline");
        }

        // decide(): the success-without-prompt rejection and friends.
        #[test]
        fn decide_all_good_is_confirmed() {
            assert_eq!(decide(0, 0, 1, true), PresenceOutcome::Confirmed);
        }

        #[test]
        fn decide_auth_failure_is_denied() {
            assert_eq!(decide(7, 0, 1, true), PresenceOutcome::Denied);
        }

        #[test]
        fn decide_success_without_prompt_is_denied() {
            assert_eq!(decide(0, 0, 0, true), PresenceOutcome::Denied);
        }

        #[test]
        fn decide_user_mismatch_is_denied() {
            assert_eq!(decide(0, 0, 1, false), PresenceOutcome::Denied);
        }

        #[test]
        fn decide_acct_mgmt_failure_is_denied() {
            assert_eq!(decide(0, 5, 1, true), PresenceOutcome::Denied);
        }
    }
}
