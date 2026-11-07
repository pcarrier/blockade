mod config;
mod control;
mod quota;

use std::{
    convert::Infallible,
    env,
    error::Error,
    future::Future,
    io::{self, Write},
    net::IpAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use hyper::{
    HeaderMap, Method, Request, Response, StatusCode, Uri, Version,
    body::{Body, Bytes, Frame, Incoming, SizeHint},
    header::{self, HeaderName, HeaderValue},
    server::conn::http1,
    service::service_fn,
};
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo, TokioTimer},
};
use maxminddb::{Reader, path};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    signal::unix::{SignalKind, signal},
    time::{self, Sleep, timeout},
};

use config::{Config, USAGE};
use quota::{Denial, Key, Ledger, Meter, Network, Policy, State, Transfer};

const MAX_BUFFER: usize = 32 * 1024;
const BODY_IDLE: Duration = Duration::from_secs(30);
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(60);

type AnyError = Box<dyn Error>;

fn main() {
    if let Err(err) = run() {
        eprintln!("blockade: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), AnyError> {
    let mut args: Vec<_> = env::args_os().skip(1).collect();
    let mut instance = String::from("default");
    if let Some(index) = args.iter().position(|arg| arg == "--instance") {
        args.remove(index);
        if args
            .get(index)
            .is_none_or(|arg| arg.as_encoded_bytes().starts_with(b"--"))
        {
            return Err("--instance requires a name".into());
        }
        instance = args
            .remove(index)
            .into_string()
            .map_err(|_| "invalid --instance name")?;
    }
    let (command, options) = args.split_first().ok_or(USAGE)?;
    let command = command.to_str().ok_or(USAGE)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match (command, options) {
        ("help" | "--help" | "-h", []) => print_usage()?,
        ("proxy", [flag]) if flag == "--help" => print_usage()?,
        ("proxy", options) => {
            let control = control::Address::new(&instance)?;
            let config = Config::parse(&instance, options)?;
            let asns = Reader::open_readfile(&config.asn_db)
                .map_err(|error| format!("ASN database {}: {error}", config.asn_db.display()))?;
            if !asns.metadata().database_type.contains("ASN") {
                return Err("--asn-db must point to an ASN MMDB file".into());
            }
            let mut ledger = Ledger::new(Policy {
                start: Instant::now(),
                epoch: SystemTime::now().duration_since(UNIX_EPOCH)?,
                interval_secs: config.interval_secs,
                intervals: config.intervals,
                max_requests: config.max_requests,
                max_bytes: config.max_bytes,
            });
            let state = State::open(
                config.state_dir.clone(),
                &mut ledger,
                config.empty_allowlist,
            )
            .map_err(|error| format!("state directory {}: {error}", config.state_dir.display()))?;
            let (state, ledger) = (Arc::new(state), Arc::new(Mutex::new(ledger)));
            runtime.block_on(serve(
                config,
                control,
                asns,
                Arc::clone(&ledger),
                Arc::clone(&state),
            ))?;
            drop(runtime);
            state.commit_blocks(&ledger, None)?;
            state.checkpoint(&ledger)?;
        }
        ("stats" | "list", []) => {
            runtime.block_on(control::call(control::Address::new(&instance)?, command))?;
        }
        ("reject" | "allow" | "clear", [ua]) => {
            let request = format!("{command} {}", reduced_ua(ua.as_encoded_bytes()));
            runtime.block_on(control::call(control::Address::new(&instance)?, &request))?;
        }
        ("unblock", [network, ua]) => {
            let network: Network = network.to_str().ok_or("invalid network")?.parse()?;
            let request = format!("unblock {network} {}", reduced_ua(ua.as_encoded_bytes()));
            runtime.block_on(control::call(control::Address::new(&instance)?, &request))?;
        }
        _ => return Err(USAGE.into()),
    }
    Ok(())
}

fn print_usage() -> io::Result<()> {
    match writeln!(io::stdout(), "{USAGE}") {
        Err(error) if error.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        result => result,
    }
}

async fn serve(
    config: Config,
    control: control::Address,
    asns: Reader<Vec<u8>>,
    ledger: Arc<Mutex<Ledger>>,
    state: Arc<State>,
) -> Result<(), AnyError> {
    let listener = TcpListener::bind(config.listen).await?;
    let control_listener = control.bind()?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;

    let mut connector = HttpConnector::new();
    connector.set_connect_timeout(Some(Duration::from_secs(5)));
    connector.set_nodelay(true);
    let client = Client::builder(TokioExecutor::new())
        .pool_timer(TokioTimer::new())
        .pool_max_idle_per_host(16)
        .http1_max_buf_size(MAX_BUFFER)
        .build(connector);
    let proxy = Arc::new(Proxy {
        upstream: config.upstream,
        host: config.host,
        trusted_proxy: config.trusted_proxy,
        garbage: config.garbage,
        asns,
        ledger: Arc::clone(&ledger),
        state: Arc::clone(&state),
        client,
    });
    tokio::spawn(control.serve(control_listener, Arc::clone(&ledger), Arc::clone(&state)));
    tokio::spawn(async move {
        let mut checkpoints =
            time::interval_at(time::Instant::now() + config.checkpoint, config.checkpoint);
        checkpoints.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
        loop {
            checkpoints.tick().await;
            let (ledger, state) = (Arc::clone(&ledger), Arc::clone(&state));
            match tokio::task::spawn_blocking(move || state.checkpoint(&ledger)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("checkpoint quotas: {error}"),
                Err(error) => eprintln!("checkpoint task: {error}"),
            }
        }
    });
    eprintln!("blockade listening on {}", listener.local_addr()?);
    tokio::select! {
        _ = terminate.recv() => {}
        _ = interrupt.recv() => {}
        _ = accept_connections(listener, proxy) => {}
    }
    Ok(())
}

async fn accept_connections(listener: TcpListener, proxy: Arc<Proxy>) {
    loop {
        let (socket, address) = match listener.accept().await {
            Ok(connection) => connection,
            Err(err) => {
                eprintln!("accept: {err}");
                time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let proxy = Arc::clone(&proxy);
        tokio::spawn(async move {
            let _ = socket.set_nodelay(true);
            let drain_upload = AtomicBool::new(false);
            let service = service_fn(|request: Request<Incoming>| async {
                let has_body = !request.body().is_end_stream();
                let response =
                    proxy
                        .forward(request, address.ip())
                        .await
                        .unwrap_or_else(|status| {
                            let mut response = proxy.error_response(status);
                            // A local rejection can leave the upload unread.
                            if has_body {
                                if matches!(response.body(), ProxyBody::Garbage(_)) {
                                    drain_upload.store(true, Ordering::Relaxed);
                                }
                                response
                                    .headers_mut()
                                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
                            }
                            response
                        });
                Ok::<_, Infallible>(response)
            });
            let connection = http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(Duration::from_secs(10))
                .max_buf_size(MAX_BUFFER)
                .serve_connection(TokioIo::new(socket), service);
            if let Ok(parts) = connection.without_shutdown().await {
                let mut socket = parts.io.into_inner();
                if socket.shutdown().await.is_ok() && drain_upload.load(Ordering::Relaxed) {
                    // A full close with unread upload data can reset the response.
                    let _ = timeout(Duration::from_secs(1), async {
                        tokio::io::copy(&mut socket, &mut tokio::io::sink()).await
                    })
                    .await;
                }
            }
        });
    }
}

struct Proxy {
    upstream: Uri,
    host: HeaderValue,
    trusted_proxy: Option<IpAddr>,
    garbage: Option<Bytes>,
    asns: Reader<Vec<u8>>,
    ledger: Arc<Mutex<Ledger>>,
    state: Arc<State>,
    client: Client<HttpConnector, ProxyBody>,
}

impl Proxy {
    fn error_response(&self, status: StatusCode) -> Response<ProxyBody> {
        if matches!(
            status,
            StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
        ) && let Some(garbage) = &self.garbage
        {
            let mut response = reject(StatusCode::OK);
            *response.body_mut() = ProxyBody::Garbage(garbage.clone());
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            );
            return response;
        }
        reject(status)
    }

    async fn forward(
        &self,
        request: Request<Incoming>,
        peer: IpAddr,
    ) -> Result<Response<ProxyBody>, StatusCode> {
        let (mut parts, body) = request.into_parts();
        if parts.method == Method::CONNECT || parts.headers.contains_key(header::UPGRADE) {
            return Err(StatusCode::NOT_IMPLEMENTED);
        }
        let path = parts.uri.path_and_query().ok_or(StatusCode::BAD_REQUEST)?;
        let mut target = self.upstream.clone().into_parts();
        target.path_and_query = Some(path.clone());
        parts.uri = Uri::from_parts(target).map_err(|_| StatusCode::BAD_REQUEST)?;
        let chunked = is_chunked(&parts.headers).ok_or(StatusCode::NOT_IMPLEMENTED)?;
        let peer = peer.to_canonical();
        let ip = if self.trusted_proxy == Some(peer) {
            forwarded_ip(&parts.headers).ok_or(StatusCode::BAD_REQUEST)?
        } else {
            peer
        };
        let asn = if ip.is_ipv6() && self.asns.metadata().ip_version == 4 {
            None
        } else {
            self.asns
                .lookup(ip)
                .and_then(|found| found.decode_path::<u32>(&path!["autonomous_system_number"]))
                .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?
        };
        let network = asn
            .filter(|&asn| asn != 0)
            .map_or(Network::Ip(ip), Network::Asn);
        let ua = reduced_ua(
            parts
                .headers
                .get(header::USER_AGENT)
                .map_or(&[], HeaderValue::as_bytes),
        );
        let meter = match Meter::admit(&self.ledger, &self.state, Key(network, ua)) {
            Ok(meter) => meter,
            Err(denial) => return Err(self.denied(denial).await),
        };

        strip_hop_headers(&mut parts.headers);
        let forwarded: Vec<_> = parts
            .headers
            .keys()
            .filter(|name| name.as_str().starts_with("x-forwarded-"))
            .cloned()
            .collect();
        for name in forwarded {
            parts.headers.remove(name);
        }
        parts.headers.remove("forwarded");
        parts.headers.remove("x-real-ip");
        parts.headers.insert(
            "x-forwarded-for",
            HeaderValue::from_str(&ip.to_string()).unwrap(),
        );
        parts.headers.insert(header::HOST, self.host.clone());
        parts.headers.append(
            header::VIA,
            HeaderValue::from_static(if parts.version == Version::HTTP_10 {
                "1.0 blockade"
            } else {
                "1.1 blockade"
            }),
        );
        if chunked {
            parts.headers.remove(header::CONTENT_LENGTH);
            parts.headers.insert(
                header::TRANSFER_ENCODING,
                HeaderValue::from_static("chunked"),
            );
        }
        parts.version = Version::HTTP_11;
        let request = Request::from_parts(parts, ProxyBody::new(body, meter.clone()));
        let response = match timeout(RESPONSE_TIMEOUT, self.client.request(request)).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                return Err(match meter.denial() {
                    Some(denial) => self.denied(denial).await,
                    None => StatusCode::BAD_GATEWAY,
                });
            }
            Err(_) => return Err(StatusCode::GATEWAY_TIMEOUT),
        };
        let (mut parts, body) = response.into_parts();
        if parts.status == StatusCode::SWITCHING_PROTOCOLS {
            return Err(StatusCode::BAD_GATEWAY);
        }
        let chunked = is_chunked(&parts.headers).ok_or(StatusCode::BAD_GATEWAY)?;
        strip_hop_headers(&mut parts.headers);
        if chunked {
            parts.headers.remove(header::CONTENT_LENGTH);
        }
        parts.version = Version::HTTP_11;
        Ok(Response::from_parts(parts, ProxyBody::new(body, meter)))
    }

    async fn denied(&self, denial: Denial) -> StatusCode {
        match denial {
            Denial::Quota => StatusCode::TOO_MANY_REQUESTS,
            Denial::Manual => StatusCode::FORBIDDEN,
            Denial::Pending => match self.state.update_blocks(&self.ledger, None).await {
                Ok(Ok(_)) => StatusCode::TOO_MANY_REQUESTS,
                error => {
                    eprintln!("save automatic block: {error:?}");
                    StatusCode::SERVICE_UNAVAILABLE
                }
            },
        }
    }
}

fn is_chunked(headers: &HeaderMap) -> Option<bool> {
    let mut values = headers.get_all(header::TRANSFER_ENCODING).iter();
    match values.next() {
        None => Some(false),
        Some(value)
            if value
                .as_bytes()
                .trim_ascii()
                .eq_ignore_ascii_case(b"chunked")
                && values.next().is_none() =>
        {
            Some(true)
        }
        _ => None,
    }
}

fn forwarded_ip(headers: &HeaderMap) -> Option<IpAddr> {
    let mut values = headers.get_all("x-forwarded-for").iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value.trim().parse::<IpAddr>().ok()?.to_canonical())
}

fn strip_hop_headers(headers: &mut HeaderMap) {
    let named: Vec<_> = headers
        .get_all(header::CONNECTION)
        .iter()
        .flat_map(|value| value.as_bytes().split(|&byte| byte == b','))
        .filter_map(|name| HeaderName::from_bytes(name.trim_ascii()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

fn reduced_ua(value: &[u8]) -> String {
    let Some(mut product) = value
        .split(|byte| byte.is_ascii_whitespace())
        .find(|part| !part.is_empty())
    else {
        return "-".into();
    };
    if let Some(slash) = product.iter().position(|&byte| byte == b'/') {
        let version = &product[slash + 1..];
        let version = version
            .strip_prefix(b"v")
            .or_else(|| version.strip_prefix(b"V"))
            .unwrap_or(version);
        if slash != 0 && version.first().is_some_and(u8::is_ascii_digit) {
            product = &product[..slash];
        }
    }
    product
        .iter()
        .take(64)
        .map(|byte| {
            if byte.is_ascii_graphic() {
                char::from(byte.to_ascii_lowercase())
            } else {
                '_'
            }
        })
        .collect()
}

fn reject(status: StatusCode) -> Response<ProxyBody> {
    let mut response = Response::new(ProxyBody::Empty);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

enum ProxyBody {
    Empty,
    Garbage(Bytes),
    Stream {
        body: Incoming,
        meter: Meter,
        idle: Pin<Box<Sleep>>,
        pending: Option<PendingFrame>,
    },
}

struct PendingFrame {
    commit: tokio::task::JoinHandle<io::Result<bool>>,
    frame: Option<Frame<Bytes>>,
}

impl ProxyBody {
    fn new(body: Incoming, meter: Meter) -> Self {
        if body.is_end_stream() {
            Self::Empty
        } else {
            Self::Stream {
                body,
                meter,
                idle: Box::pin(time::sleep(BODY_IDLE)),
                pending: None,
            }
        }
    }
}

impl Body for ProxyBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        if let Self::Garbage(bytes) = &mut *self {
            return Poll::Ready(
                (!bytes.is_empty()).then(|| Ok(Frame::data(std::mem::take(bytes)))),
            );
        }
        let Self::Stream {
            body,
            meter,
            idle,
            pending,
        } = &mut *self
        else {
            return Poll::Ready(None);
        };
        let error = if let Some(wait) = pending {
            match Pin::new(&mut wait.commit).poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(Ok(_))) => {
                    let frame = wait.frame.take();
                    *pending = None;
                    if let Some(frame) = frame {
                        idle.as_mut().reset(time::Instant::now() + BODY_IDLE);
                        return Poll::Ready(Some(Ok(frame)));
                    }
                    io::Error::other("blocked by blockade")
                }
                Poll::Ready(error) => {
                    eprintln!("save automatic block: {error:?}");
                    io::Error::other("failed to save automatic block")
                }
            }
        } else {
            match Pin::new(body).poll_frame(cx) {
                Poll::Pending if idle.as_mut().poll(cx).is_pending() => return Poll::Pending,
                Poll::Pending => io::Error::from(io::ErrorKind::TimedOut),
                Poll::Ready(Some(Err(err))) => io::Error::other(err),
                Poll::Ready(Some(Ok(frame))) if frame.data_ref().is_some() => {
                    match meter.transfer(frame.data_ref().unwrap().len()) {
                        Transfer::Pass => {
                            idle.as_mut().reset(time::Instant::now() + BODY_IDLE);
                            return Poll::Ready(Some(Ok(frame)));
                        }
                        Transfer::Stop => io::Error::other("blocked by blockade"),
                        Transfer::Commit { forward } => {
                            *pending = Some(PendingFrame {
                                commit: meter.commit(),
                                frame: forward.then_some(frame),
                            });
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                    }
                }
                Poll::Ready(_) => {
                    // HTTP/1 trailers terminate the stream and are not forwarded.
                    *self = Self::Empty;
                    return Poll::Ready(None);
                }
            }
        };
        *self = Self::Empty;
        Poll::Ready(Some(Err(error)))
    }

    fn is_end_stream(&self) -> bool {
        match self {
            Self::Empty => true,
            Self::Garbage(bytes) => bytes.is_empty(),
            Self::Stream { body, pending, .. } => pending.is_none() && body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            Self::Empty => SizeHint::with_exact(0),
            Self::Garbage(bytes) => SizeHint::with_exact(bytes.len() as u64),
            Self::Stream { body, .. } => body.size_hint(),
        }
    }
}
