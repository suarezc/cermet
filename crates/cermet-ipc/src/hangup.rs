//! Pipe-hangup observation: observe "the client closed its end" on a read fd WITHOUT
//! consuming any data, so a stdio server can anchor its shutdown clock at the actual close — even
//! while an arbitrarily large unread backlog sits in the kernel pipe and the reader thread is
//! parked on a full queue. EOF-as-read (the reader consuming past the last byte) only surfaces
//! after the whole backlog drains; hangup is the independent, admission-free signal.
//!
//! Platform split: Linux `poll(2)` reports `POLLHUP` on a pipe's read end the moment the writer
//! closes, even with unread data. macOS WITHHOLDS `POLLHUP` until the pipe is drained — there the
//! reliable signal is kqueue's `EV_EOF` on `EVFILT_READ`, which is set at close regardless of
//! buffered data.

use std::os::fd::RawFd;

/// True once the peer end of `fd` is hung up — the writer closed, regardless of how much unread
/// data remains. Non-consuming, non-blocking. An observation ERROR reports `true` fail-closed: an
/// unobservable stream is treated as gone, never as healthy forever. The caller must keep `fd`
/// open for the duration of the call (the watcher thread observes the fd only while the owning
/// reader is alive).
#[cfg(not(target_os = "macos"))]
pub fn hung_up(fd: RawFd) -> bool {
    let mut fds = [nix::poll::PollFd::new(fd, nix::poll::PollFlags::empty())];
    match nix::poll::poll(&mut fds, 0) {
        Ok(_) => fds[0].revents().is_some_and(|r| {
            r.intersects(
                nix::poll::PollFlags::POLLHUP
                    | nix::poll::PollFlags::POLLERR
                    | nix::poll::PollFlags::POLLNVAL,
            )
        }),
        Err(_) => true,
    }
}

/// macOS: kqueue `EV_EOF` (see the module doc — `poll` here withholds `POLLHUP` while the pipe
/// still holds data, which is exactly the backlog case this exists for).
#[cfg(target_os = "macos")]
pub fn hung_up(fd: RawFd) -> bool {
    use nix::sys::event::{kevent, kqueue, EventFilter, EventFlag, FilterFlag, KEvent};

    let Ok(kq) = kqueue() else {
        return true;
    };
    let changes = [KEvent::new(
        fd as usize,
        EventFilter::EVFILT_READ,
        EventFlag::EV_ADD | EventFlag::EV_ONESHOT,
        FilterFlag::empty(),
        0,
        0,
    )];
    let mut events = [KEvent::new(
        0,
        EventFilter::EVFILT_READ,
        EventFlag::empty(),
        FilterFlag::empty(),
        0,
        0,
    )];
    // Zero timeout: one non-blocking observation per call.
    let res = match kevent(kq, &changes, &mut events, 0) {
        Ok(0) => false,
        Ok(_) => events[0]
            .flags()
            .intersects(EventFlag::EV_EOF | EventFlag::EV_ERROR),
        Err(_) => true,
    };
    let _ = nix::unistd::close(kq);
    res
}
