//! Length-prefixed JSON framing.

use std::io::{self, Read, Write};

use serde::de::DeserializeOwned;
use serde::Serialize;
use thiserror::Error;
use zeroize::Zeroizing;

/// Maximum inbound (request) frame body size: 64 KiB.
pub const MAX_FRAME: u32 = 64 * 1024;

/// Maximum outbound (response) frame body size: 4 MiB.
pub const MAX_RESPONSE_FRAME: u32 = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum CodecError {
    /// The declared length exceeds [`MAX_FRAME`].
    #[error("frame too large: {0} bytes exceeds MAX_FRAME ({max})", max = MAX_FRAME)]
    FrameTooLarge(u32),
    /// The stream ended before the declared bytes were read.
    #[error("unexpected eof while reading frame")]
    UnexpectedEof,
    /// The body was not valid UTF-8 JSON for the target type.
    #[error("frame decode failed: {0}")]
    Decode(#[from] serde_json::Error),
    /// Serializing the value to write failed.
    #[error("frame encode failed: {0}")]
    Encode(serde_json::Error),
    /// Underlying transport error.
    #[error("frame io error: {0}")]
    Io(io::Error),
}

pub type Result<T> = std::result::Result<T, CodecError>;

/// Write `value` as one inbound length-prefixed JSON frame, bounded by [`MAX_FRAME`].
pub fn write_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> Result<()> {
    write_frame_bounded(w, value, MAX_FRAME)
}

/// Write a response frame, bounded by [`MAX_RESPONSE_FRAME`].
pub fn write_response_frame<W: Write, T: Serialize>(w: &mut W, value: &T) -> Result<()> {
    write_frame_bounded(w, value, MAX_RESPONSE_FRAME)
}

/// Write `value` as one length-prefixed JSON frame, bounded by `max`.
pub fn write_frame_bounded<W: Write, T: Serialize>(w: &mut W, value: &T, max: u32) -> Result<()> {
    let body = Zeroizing::new(serde_json::to_vec(value).map_err(CodecError::Encode)?);
    if body.len() as u64 > max as u64 {
        return Err(CodecError::FrameTooLarge(
            body.len().min(u32::MAX as usize) as u32
        ));
    }
    let len = body.len() as u32;
    w.write_all(&len.to_le_bytes()).map_err(CodecError::Io)?;
    w.write_all(body.as_slice()).map_err(CodecError::Io)?;
    w.flush().map_err(CodecError::Io)?;
    Ok(())
}

/// Read exactly `buf.len()` bytes, mapping a clean EOF to [`CodecError::UnexpectedEof`].
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<()> {
    match r.read_exact(buf) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(CodecError::UnexpectedEof),
        Err(e) => Err(CodecError::Io(e)),
    }
}

/// Read one inbound length-prefixed JSON frame and decode it as `T`, bounded by [`MAX_FRAME`].
pub fn read_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    read_frame_bounded(r, MAX_FRAME)
}

/// Read a response frame, bounded by [`MAX_RESPONSE_FRAME`].
pub fn read_response_frame<R: Read, T: DeserializeOwned>(r: &mut R) -> Result<T> {
    read_frame_bounded(r, MAX_RESPONSE_FRAME)
}

/// Read one length-prefixed JSON frame and decode it as `T`, bounding the declared length by `max`.
pub fn read_frame_bounded<R: Read, T: DeserializeOwned>(r: &mut R, max: u32) -> Result<T> {
    let mut len_buf = [0u8; 4];
    read_exact_or_eof(r, &mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);

    if len > max {
        return Err(CodecError::FrameTooLarge(len));
    }

    let mut body = Zeroizing::new(vec![0u8; len as usize]);
    read_exact_or_eof(r, body.as_mut_slice())?;
    let value = serde_json::from_slice(body.as_slice())?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::os::unix::io::{FromRawFd, IntoRawFd};
    use std::os::unix::net::UnixStream;

    use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct Msg {
        kind: String,
        n: u32,
    }

    fn socketpair_streams() -> (UnixStream, UnixStream) {
        let (a, b) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .expect("socketpair");
        let a = unsafe { UnixStream::from_raw_fd(a.into_raw_fd()) };
        let b = unsafe { UnixStream::from_raw_fd(b.into_raw_fd()) };
        (a, b)
    }

    #[test]
    fn roundtrip_frame_over_socketpair() {
        let (mut tx, mut rx) = socketpair_streams();
        let msg = Msg {
            kind: "request".into(),
            n: 7,
        };
        write_frame(&mut tx, &msg).expect("write");
        let got: Msg = read_frame(&mut rx).expect("read");
        assert_eq!(got, msg);
    }

    #[test]
    fn oversize_length_prefix_rejected_without_alloc() {
        let mut buf: Vec<u8> = Vec::new();
        buf.write_all(&(MAX_FRAME + 1).to_le_bytes()).unwrap();
        let mut cur = Cursor::new(buf);
        let res: Result<Msg> = read_frame(&mut cur);
        match res {
            Err(CodecError::FrameTooLarge(n)) => assert_eq!(n, MAX_FRAME + 1),
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn oversize_response_under_outbound_cap_roundtrips() {
        let big = Msg {
            kind: "x".repeat(MAX_FRAME as usize + 1024),
            n: 42,
        };
        let serialized = serde_json::to_vec(&big).unwrap();
        assert!(
            serialized.len() as u32 > MAX_FRAME,
            "test body must exceed the request cap"
        );
        assert!(
            (serialized.len() as u32) < MAX_RESPONSE_FRAME,
            "test body must stay under the response cap"
        );

        let mut reject_buf: Vec<u8> = Vec::new();
        let rejected = write_frame(&mut reject_buf, &big);
        assert!(
            matches!(rejected, Err(CodecError::FrameTooLarge(_))),
            "the request path still rejects > 64 KiB, got {rejected:?}"
        );

        let (mut tx, mut rx) = socketpair_streams();
        let writer = std::thread::spawn(move || {
            write_response_frame(&mut tx, &big).expect("write_response_frame");
            big
        });
        let got: Msg = read_response_frame(&mut rx).expect("read_response_frame");
        let sent = writer.join().unwrap();
        assert_eq!(got, sent, "oversize response roundtrips intact");
    }

    #[test]
    fn truncated_and_malformed_frames_error() {
        {
            let body = br#"{"kind":"x","n":1}"#;
            let claimed = body.len() as u32;
            let mut buf = Vec::new();
            buf.write_all(&claimed.to_le_bytes()).unwrap();
            buf.write_all(&body[..body.len() - 1]).unwrap();
            let mut cur = Cursor::new(buf);
            let res: Result<Msg> = read_frame(&mut cur);
            assert!(
                matches!(res, Err(CodecError::UnexpectedEof)),
                "expected UnexpectedEof, got {res:?}"
            );
        }
        {
            let body = b"not json at all";
            let claimed = body.len() as u32;
            let mut buf = Vec::new();
            buf.write_all(&claimed.to_le_bytes()).unwrap();
            buf.write_all(body).unwrap();
            let mut cur = Cursor::new(buf);
            let res: Result<Msg> = read_frame(&mut cur);
            assert!(
                matches!(res, Err(CodecError::Decode(_))),
                "expected Decode, got {res:?}"
            );
        }
    }
}
