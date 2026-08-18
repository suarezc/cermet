//! cermetd's loopback relay listener.
//!
//! This module is a pure HTTP adapter and NOTHING else. It parses one request off a loopback
//! connection, hands (handle, method, target, headers, body) to the broker, and writes the broker's
//! answer back. It makes no authorization decision, keeps no session state, and never touches a
//! credential: the trust boundary is the loopback socket, and it is enforced ONCE — in
//! `cermet-core::broker::relay` — per the one-validation-per-crossing rule.
//!
//! Why an HTTP server at all: the native `vercel` CLI is pointed here with its undocumented `--api`
//! flag and speaks real HTTP/1.1 (keep-alive, chunked upload bodies). Reimplementing that parser is
//! the in-house reimplementation the never-reinvent-the-wheel ruling forbids, so hyper serves it.
//!
//! T3 (peer uids on the box): the listener binds LOOPBACK ONLY and every request must carry a live
//! handle in `Authorization: Bearer`. No handle ⇒ a refusal with nothing else revealed (409, and it
//! says so in words). A handle stolen from
//! `/proc/<pid>/cmdline` is a named, accepted cost.
//!
//! The answer is written back AS IT ARRIVES, and the whole hop runs HERE. The broker returns a
//! verdict and, when the hop is authorized, a credentialed job it has not sent. This module runs that
//! job on a worker thread — connect, send, head, body — writes the head the moment it lands, and
//! pumps the body into a chunked hyper body, so a `follow=1` build-log read reaches the native client
//! line by line instead of after the upstream finishes. All of it is plumbing, not policy: it makes
//! no decision, it cannot read the credential sealed in the job, and it hands the finished hop back
//! to the core for its audit row and the session's receipt. The point of running it here is that an
//! upstream which is slow, silent, or streaming for minutes costs one worker thread and never the
//! broker actor.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use cermet_broker_actor::BrokerHandle;
use cermet_core::broker::{
    RelayHopHead, RelayHopJob, RelayHopResponse, RelayHopStart, RelayHopStream,
};
use cermet_core::RelayConfig;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Frame, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;

/// How many pumped chunks may sit between the upstream reader and the loopback socket. A small
/// number is the point: a slow native client must back-pressure the upstream read, not accumulate
/// the body in daemon memory — which is what this whole change exists to stop doing.
const RELAY_STREAM_QUEUE: usize = 4;

/// Every relay response, streamed or complete, in one body type.
type RelayBody = BoxBody<Bytes, Infallible>;

/// The streamed half: chunks the pump task pushes as the upstream produces them. Its length is
/// unknown, so hyper frames it `Transfer-Encoding: chunked` and each chunk reaches the native client
/// as it lands — the point being that a `follow=1` build-log read must not sit blind while the
/// deployment goes READY.
struct ChunkBody {
    rx: tokio::sync::mpsc::Receiver<Bytes>,
}

impl Body for ChunkBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Infallible>>> {
        self.get_mut()
            .rx
            .poll_recv(cx)
            .map(|chunk| chunk.map(|bytes| Ok(Frame::data(bytes))))
    }
}

/// Bind the relay listener and serve it until the process exits. Returns `Ok(None)` when the relay is
/// disabled by config (`relay_listen = ""`), and `Err` when a configured address cannot be bound or
/// is not a loopback address — binding a routable interface would publish the handle door, so it fails
/// closed rather than serving something wider than the design.
pub async fn serve(relay: RelayConfig, broker: BrokerHandle) -> Result<Option<SocketAddr>, String> {
    if !relay.enabled() {
        return Ok(None);
    }
    let addr = validate_listen(&relay)?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|error| format!("cannot bind the relay listener on {addr}: {error}"))?;
    let bound = listener
        .local_addr()
        .map_err(|error| format!("cannot read the relay listener address: {error}"))?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                continue;
            };
            let broker = broker.clone();
            let max_body_bytes = relay.max_body_bytes;
            tokio::spawn(async move {
                let service = service_fn(move |request| {
                    let broker = broker.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(
                            hop(broker, request, max_body_bytes).await,
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok(Some(bound))
}

/// One request: extract the handle, buffer the body under the declared cap, ask the broker, answer.
async fn hop(
    broker: BrokerHandle,
    request: Request<Incoming>,
    max_body_bytes: usize,
) -> Response<RelayBody> {
    let method = request.method().as_str().to_string();
    // The request TARGET verbatim (path + query), which is what the predicate is written against.
    let target = request
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_default();
    let handle = bearer_handle(&request).unwrap_or_default();
    let headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect();
    // Bounded read: an oversized body never becomes daemon memory. The broker also enforces the cap
    // (it owns the setting), and refusing here is what keeps the read itself bounded.
    let body = match Limited::new(request.into_body(), max_body_bytes)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes().to_vec(),
        Err(_) => return status_only(StatusCode::PAYLOAD_TOO_LARGE),
    };
    match broker
        .relay_hop_start(handle, method, target, headers, body)
        .await
    {
        Ok(RelayHopStart::Complete(response)) => render(response),
        Ok(RelayHopStart::Job(job)) => run_hop(broker, *job).await,
        // A broker-side fault (audit or vault) is not a client error and never leaks its detail: the
        // native client gets a bare 503 and the operator gets the audited refusal.
        Err(_) => status_only(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// Perform ONE authorized hop and write it back as it arrives.
///
/// The ENTIRE hop — connect, send, wait for the head, pump the body — runs on a blocking worker
/// thread and never on the broker actor, so an upstream that is slow, silent, or streaming a build
/// log for minutes costs one worker thread and nothing else. Nothing here decides anything: the
/// verdict is already spent, the credential is sealed inside the job, and when the hop ends for any
/// reason it goes back to the core, which writes its audit row and the session's receipt.
async fn run_hop(broker: BrokerHandle, job: RelayHopJob) -> Response<RelayBody> {
    let (chunks, rx) = tokio::sync::mpsc::channel::<Bytes>(RELAY_STREAM_QUEUE);
    let (head_tx, head_rx) =
        tokio::sync::oneshot::channel::<Option<(String, bool, RelayHopHead)>>();
    let (done, finished) = tokio::sync::oneshot::channel::<RelayHopStream>();
    tokio::task::spawn_blocking(move || {
        let mut stream = job.run();
        let head = stream
            .head()
            .cloned()
            .map(|head| (stream.handle().to_string(), stream.effect(), head));
        let _ = head_tx.send(head);
        while let Some(chunk) = stream.next_chunk() {
            if chunk.is_empty() {
                continue;
            }
            // The client hung up: stop pumping, and still close the hop below.
            if chunks.blocking_send(Bytes::from(chunk)).is_err() {
                break;
            }
        }
        let _ = done.send(stream);
    });

    // Every hop that started is closed by the core, head or no head.
    let closer = broker.clone();
    tokio::spawn(async move {
        if let Ok(stream) = finished.await {
            let _ = closer.relay_hop_complete(stream).await;
        }
    });

    let Ok(Some((handle, effect, head))) = head_rx.await else {
        // No head ever arrived, or the worker died: the upstream is unavailable to this client. The
        // failure row is the core's, and the task above writes it.
        return render(RelayHopResponse::upstream_unavailable());
    };
    // What the status alone decides lands BEFORE the client sees the status — a definite provider
    // 4xx on the effect hop releases the `once` effect, so the native two-phase create's immediate
    // retry cannot meet a stale refusal.
    let _ = broker.relay_hop_head(handle, effect, head.status).await;

    let mut builder = Response::builder()
        .status(StatusCode::from_u16(head.status).unwrap_or(StatusCode::BAD_GATEWAY));
    for (name, value) in &head.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(BodyExt::boxed(ChunkBody { rx }))
        .unwrap_or_else(|_| status_only(StatusCode::BAD_GATEWAY))
}

/// The handle out of `Authorization: Bearer <handle>`. Case-insensitive scheme, exactly like every
/// HTTP client writes it; anything else yields no handle, which the broker refuses as an unknown one.
fn bearer_handle(request: &Request<Incoming>) -> Option<String> {
    let value = request.headers().get(hyper::header::AUTHORIZATION)?;
    let value = value.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| token.trim().to_string())
}

fn render(response: RelayHopResponse) -> Response<RelayBody> {
    let mut builder = Response::builder()
        .status(StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY));
    for (name, value) in &response.headers {
        builder = builder.header(name, value);
    }
    builder
        .body(BodyExt::boxed(Full::new(Bytes::from(response.body))))
        .unwrap_or_else(|_| status_only(StatusCode::BAD_GATEWAY))
}

fn status_only(status: StatusCode) -> Response<RelayBody> {
    Response::builder()
        .status(status)
        .body(BodyExt::boxed(Full::new(Bytes::new())))
        .expect("a status-only response is always buildable")
}

/// The address check `serve` applies, split out so it is testable without binding a port.
pub(crate) fn validate_listen(relay: &RelayConfig) -> Result<SocketAddr, String> {
    let addr: SocketAddr = relay
        .listen
        .parse()
        .map_err(|_| format!("relay_listen `{}` is not a host:port address", relay.listen))?;
    if !addr.ip().is_loopback() {
        return Err(format!(
            "relay_listen `{}` is not a loopback address; the relay's handle door is only ever \
             reachable from this host",
            relay.listen
        ));
    }
    Ok(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(listen: &str) -> RelayConfig {
        RelayConfig {
            listen: listen.to_string(),
            ..RelayConfig::default()
        }
    }

    #[test]
    fn the_default_listen_authority_is_loopback_and_declared() {
        let default = RelayConfig::default();
        assert_eq!(default.listen, "127.0.0.1:7133");
        assert_eq!(default.base_url(), "http://127.0.0.1:7133");
        assert!(default.enabled());
        assert!(!config("").enabled(), "an empty listen disables the relay");
    }

    #[tokio::test]
    async fn a_routable_or_malformed_listen_address_refuses_to_serve() {
        // The listener is the handle door; a non-loopback bind would publish it to the network. There
        // is no "warn and serve" here.
        for listen in ["0.0.0.0:7133", "192.0.2.1:7133", "not-an-address", "7133"] {
            let error = crate::relay::validate_listen(&config(listen))
                .expect_err("a non-loopback or malformed listen address is refused");
            assert!(
                error.contains("loopback") || error.contains("host:port"),
                "{listen}: {error}"
            );
        }
        for listen in ["127.0.0.1:7133", "127.0.0.1:0", "[::1]:7133"] {
            crate::relay::validate_listen(&config(listen)).expect("a loopback address is accepted");
        }
    }
}
