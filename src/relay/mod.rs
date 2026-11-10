//! Per-launch HTTP CONNECT relay for the macOS socket policy.
mod activity;
mod process;
#[cfg(test)]
mod testing;
mod upstream;
mod vpn;
mod vpn_dns;

use std::{
    convert::Infallible,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    os::unix::process::ExitStatusExt,
    pin::Pin,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicI32, Ordering},
    },
    time::Duration,
};

use anyhow::{Context, Error, Result, anyhow};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::Empty;
use hyper::{
    body::{Body, Bytes, Incoming},
    server::conn::http1,
    service::service_fn,
    upgrade,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use reqwest::Url;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    signal::unix::{SignalKind, signal},
    sync::mpsc,
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};

use crate::{
    notice::{self, Level},
    profile::ExitCheckInterval,
    proxy::{self, ExitPolicy, Probe},
};
use activity::{Activity, Cadence, Observed, SAMPLE_INTERVAL};
use process::ChildGroup;
use upstream::Upstream;
use vpn::Vpn;

pub(crate) fn vpn_interfaces() -> Result<Vec<String>> {
    vpn::active_interfaces()
}

const MAX_CONNECTIONS: usize = 128;
const RELAY_USER: &str = "claude-wrapper";
static FOREGROUND_CHILD: AtomicI32 = AtomicI32::new(0);

struct ForwardInterrupts(Vec<(i32, libc::sigaction)>);

unsafe extern "C" fn forward_interrupt(
    number: i32,
    info: *mut libc::siginfo_t,
    _: *mut libc::c_void,
) {
    let pid = FOREGROUND_CHILD.load(Ordering::Relaxed);
    unsafe {
        let saved_errno = *libc::__error();
        // Kernel terminal signals already reach every process in the foreground group.
        if pid > 0 && !info.is_null() && (*info).si_pid != 0 {
            libc::kill(-pid, number);
        }
        *libc::__error() = saved_errno;
    }
}

impl ForwardInterrupts {
    fn install(pid: u32) -> Result<Self> {
        let mut installed = Self(Vec::new());
        FOREGROUND_CHILD.store(pid as i32, Ordering::Relaxed);
        for number in [libc::SIGINT, libc::SIGQUIT] {
            unsafe {
                let mut previous: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(number, std::ptr::null(), &mut previous) != 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("could not inspect interrupt handler");
                }
                if previous.sa_sigaction != libc::SIG_IGN {
                    let mut action: libc::sigaction = std::mem::zeroed();
                    action.sa_sigaction = forward_interrupt as *const () as libc::sighandler_t;
                    action.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
                    libc::sigemptyset(&mut action.sa_mask);
                    if libc::sigaction(number, &action, std::ptr::null_mut()) != 0 {
                        return Err(std::io::Error::last_os_error())
                            .context("could not forward interrupts");
                    }
                    installed.0.push((number, previous));
                }
            }
        }
        Ok(installed)
    }
}

impl Drop for ForwardInterrupts {
    fn drop(&mut self) {
        FOREGROUND_CHILD.store(0, Ordering::Relaxed);
        for (number, previous) in &self.0 {
            unsafe { libc::sigaction(*number, previous, std::ptr::null_mut()) };
        }
    }
}

struct State {
    backend: Backend,
    auth: HeaderValue,
    probe_auth: HeaderValue,
    activity: Option<Arc<Activity>>,
}

enum Backend {
    Proxy(Upstream),
    Vpn(Vpn),
}

trait RelayStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> RelayStream for T {}

impl Backend {
    async fn connect(&self, authority: &http::uri::Authority) -> Result<Box<dyn RelayStream>> {
        match self {
            Self::Proxy(proxy) => Ok(Box::new(proxy.connect(authority).await?)),
            Self::Vpn(vpn) => Ok(Box::new(vpn.connect(authority).await?)),
        }
    }
}

struct Session {
    url: Url,
    #[cfg(test)]
    probe_url: Url,
    probe: Probe,
    activity: Option<Arc<Activity>>,
    server: Pin<Box<dyn Future<Output = Error>>>,
    listener: Arc<TcpListener>,
}

#[derive(Debug)]
pub struct Preflight {
    pub exit_ip: IpAddr,
    pub api_status: Option<reqwest::StatusCode>,
    pub vpn_interface: Option<String>,
}

impl Session {
    async fn start(upstream_url: &Url, exit: ExitPolicy<'_>, adaptive: bool) -> Result<Self> {
        let upstream = Upstream::resolve(upstream_url).await?;
        Self::with_backend(Backend::Proxy(upstream), exit, adaptive).await
    }

    async fn start_vpn(interface: &str, exit: ExitPolicy<'_>, adaptive: bool) -> Result<Self> {
        let vpn = Vpn::new(interface)?;
        Self::with_backend(Backend::Vpn(vpn), exit, adaptive).await
    }

    async fn with_backend(backend: Backend, exit: ExitPolicy<'_>, adaptive: bool) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("could not bind a per-launch loopback relay")?;
        let mut secret = [0; 48];
        getrandom::fill(&mut secret).map_err(|_| anyhow!("could not create a relay credential"))?;
        let address = listener.local_addr()?;
        let (url, auth) = authenticated_url(address, &secret[..24])?;
        let (probe_url, probe_auth) = authenticated_url(address, &secret[24..])?;
        let activity = adaptive.then(|| Arc::new(Activity::default()));
        let state = Arc::new(State {
            backend,
            auth,
            probe_auth,
            activity: activity.clone(),
        });
        let listener = Arc::new(listener);
        let probe = Probe::new(&probe_url, exit)?;
        Ok(Self {
            url,
            #[cfg(test)]
            probe_url,
            probe,
            activity,
            server: Box::pin(serve(Arc::clone(&listener), state)),
            listener,
        })
    }

    async fn check(&mut self) -> Result<IpAddr> {
        tokio::select! {
            failure = &mut self.server => Err(failure),
            result = self.probe.check() => result,
        }
    }

    async fn preflight(&mut self, api: Option<&Url>) -> Result<Preflight> {
        let exit_ip = self.check().await?;
        let api_status = if let Some(api) = api {
            Some(tokio::select! {
                failure = &mut self.server => return Err(failure),
                result = self.probe.check_api(api) => result?,
            })
        } else {
            None
        };
        tokio::select! {
            failure = &mut self.server => return Err(failure),
            result = self.probe.learn_ip(exit_ip) => result?,
        }
        Ok(Preflight {
            exit_ip,
            api_status,
            vpn_interface: None,
        })
    }

    async fn supervise(mut self, command: Command, health_interval: Duration) -> Result<i32> {
        let mut term = signal(SignalKind::terminate()).context("could not handle termination")?;
        let mut hangup =
            signal(SignalKind::hangup()).context("could not handle terminal hangup")?;
        let mut child = ChildGroup::spawn(command).context("could not start the guarded target")?;
        let interrupts = ForwardInterrupts::install(child.id())?;

        enum Outcome {
            Child(std::io::Result<()>),
            Relay(Error),
            Signal(i32),
        }

        let outcome = tokio::select! {
            biased;
            failure = &mut self.server => Outcome::Relay(failure),
            failure = monitor(&self.probe, health_interval, self.activity.as_deref()) => Outcome::Relay(failure),
            status = child.wait_for_exit() => Outcome::Child(status),
            _ = term.recv() => Outcome::Signal(libc::SIGTERM),
            _ = hangup.recv() => Outcome::Signal(libc::SIGHUP),
        };
        drop(interrupts);
        // Abort tunnels while reserving the endpoint until group cleanup completes.
        let Session {
            server, listener, ..
        } = self;
        drop(server);
        let _endpoint_reservation = listener;
        let stop_signal = match &outcome {
            Outcome::Signal(number) => *number,
            _ => libc::SIGTERM,
        };
        let status = child
            .terminate(stop_signal)
            .await
            .context("could not stop the guarded process group")?;
        match outcome {
            Outcome::Child(waited) => {
                waited.context("could not wait for the guarded target")?;
                Ok(status
                    .code()
                    .unwrap_or_else(|| 128 + status.signal().unwrap_or(1)))
            }
            Outcome::Relay(error) => {
                Err(error.context("guarded session ended after relay verification failed"))
            }
            Outcome::Signal(signal) => Ok(128 + signal),
        }
    }
}

fn authenticated_url(address: SocketAddr, secret: &[u8]) -> Result<(Url, HeaderValue)> {
    let password = URL_SAFE_NO_PAD.encode(secret);
    let mut url = Url::parse(&format!("http://{address}"))?;
    url.set_username(RELAY_USER)
        .map_err(|_| anyhow!("invalid relay URL"))?;
    url.set_password(Some(&password))
        .map_err(|_| anyhow!("invalid relay URL"))?;
    let auth = HeaderValue::from_str(&format!(
        "Basic {}",
        STANDARD.encode(format!("{RELAY_USER}:{password}"))
    ))?;
    Ok((url, auth))
}

async fn monitor(probe: &Probe, interval: Duration, activity: Option<&Activity>) -> Error {
    let mut last_check = Instant::now();
    let mut last_sample = last_check;
    let mut next_check = last_check + interval;
    let mut cadence = Cadence::default();
    loop {
        let next_sample = last_sample + SAMPLE_INTERVAL;
        let wake = if activity.is_some() {
            next_sample.min(next_check)
        } else {
            next_check
        };
        sleep_until(wake).await;
        let now = Instant::now();
        if let Some(activity) = activity
            && now >= next_sample
        {
            cadence.observe(activity.take(), now - last_sample);
            last_sample = now;
            next_check = next_check.min(last_check + cadence.interval(interval));
        }
        if now < next_check {
            continue;
        }
        if let Err(error) = probe.check().await {
            return error.context("runtime proxy check failed");
        }
        last_check = Instant::now();
        next_check = last_check + interval;
    }
}

async fn serve(listener: Arc<TcpListener>, state: Arc<State>) -> Error {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = connections.join_next(), if !connections.is_empty() => {}
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(connection) => connection,
                    Err(error) => return Error::new(error).context("relay listener failed"),
                };
                if peer.ip().is_loopback() && connections.len() < MAX_CONNECTIONS {
                    connections.spawn(handle(stream, Arc::clone(&state)));
                }
            }
        }
    }
}

fn reply(status: StatusCode) -> Response<Empty<Bytes>> {
    let mut response = Response::new(Empty::new());
    *response.status_mut() = status;
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response.headers_mut().insert(
            header::PROXY_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"claude-wrapper\""),
        );
    }
    response
}

async fn handle(stream: TcpStream, state: Arc<State>) {
    let (tunnel_tx, mut tunnel_rx) = mpsc::channel(1);
    let service = service_fn(move |mut request: Request<Incoming>| {
        let state = Arc::clone(&state);
        let tunnel_tx = tunnel_tx.clone();
        async move {
            let response = async {
                let mut auth = request
                    .headers()
                    .get_all(header::PROXY_AUTHORIZATION)
                    .iter();
                let first = auth.next();
                let client = first == Some(&state.auth);
                if (!client && first != Some(&state.probe_auth)) || auth.next().is_some() {
                    return reply(StatusCode::PROXY_AUTHENTICATION_REQUIRED);
                }
                if request.method() != Method::CONNECT {
                    return reply(StatusCode::METHOD_NOT_ALLOWED);
                }
                let Some(authority) = request.uri().authority() else {
                    return reply(StatusCode::BAD_REQUEST);
                };
                if request.uri().scheme().is_some()
                    || request.uri().path_and_query().is_some()
                    || authority.as_str().contains('@')
                    || !authority.port_u16().is_some_and(|port| port > 0)
                    || request.body().size_hint().exact() != Some(0)
                {
                    return reply(StatusCode::BAD_REQUEST);
                }
                let tunnel = match state.backend.connect(authority).await {
                    Ok(tunnel) => tunnel,
                    Err(error) => {
                        notice::emit(Level::Error, format_args!("relay tunnel failed: {error:#}"));
                        return reply(StatusCode::BAD_GATEWAY);
                    }
                };
                let activity = if client { state.activity.clone() } else { None };
                if tunnel_tx
                    .try_send((upgrade::on(&mut request), tunnel, activity))
                    .is_err()
                {
                    return reply(StatusCode::SERVICE_UNAVAILABLE);
                }
                reply(StatusCode::OK)
            }
            .await;
            Ok::<_, Infallible>(response)
        }
    });

    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(5))
        .max_buf_size(16 * 1024)
        .max_headers(32)
        .keep_alive(false)
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();

    if let Ok(Ok(())) = timeout(Duration::from_secs(15), connection).await
        && let Ok((upgrade, mut upstream, activity)) = tunnel_rx.try_recv()
        && let Ok(client) = upgrade.await
    {
        let mut client = TokioIo::new(client);
        if let Some(activity) = activity {
            activity.connected();
            let mut observed = Observed {
                stream: client,
                activity: &activity,
            };
            let _ = tokio::io::copy_bidirectional(&mut observed, &mut upstream).await;
        } else {
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
    }
}

pub fn doctor(upstream_url: &Url, exit: ExitPolicy<'_>, api: Option<&Url>) -> Result<Preflight> {
    proxy::run_network(async {
        Session::start(upstream_url, exit, false)
            .await?
            .preflight(api)
            .await
    })
}

pub fn run(
    upstream_url: &Url,
    exit: ExitPolicy<'_>,
    api: Option<&Url>,
    interval: ExitCheckInterval,
    build_command: impl FnOnce(&Url) -> Result<Command>,
) -> Result<i32> {
    proxy::run_network(async {
        let mut session = Session::start(upstream_url, exit, interval.is_auto()).await?;
        let preflight = session.preflight(api).await?;
        launch(session, preflight, exit.country, interval, build_command).await
    })
}

async fn verified_vpn(
    interface: &str,
    exit: ExitPolicy<'_>,
    api: Option<&Url>,
    adaptive: bool,
) -> Result<(Session, Preflight)> {
    let mut failures = Vec::new();
    let mut exit_rejection = None;
    for name in vpn::candidates(interface)? {
        let attempt = async {
            let mut session = Session::start_vpn(&name, exit, adaptive).await?;
            let preflight = session.preflight(api).await?;
            Ok::<_, Error>((session, preflight))
        }
        .await;
        match attempt {
            Ok((session, mut preflight)) => {
                preflight.vpn_interface = Some(name);
                return Ok((session, preflight));
            }
            Err(error) => {
                failures.push(format!("{name}: {error:#}"));
                if error.is::<proxy::UnexpectedExitCountry>() || error.is::<proxy::ExitIpError>() {
                    exit_rejection.get_or_insert(error);
                }
            }
        }
    }
    let message = format!(
        "VPN preflight failed ({}). Select another tunnel or use the VPN app's HTTP(S) proxy",
        failures.join(" | ")
    );
    Err(match exit_rejection {
        Some(error) => error.context(message),
        None => anyhow!(message),
    })
}

pub fn doctor_vpn(interface: &str, exit: ExitPolicy<'_>, api: Option<&Url>) -> Result<Preflight> {
    proxy::run_network(async { Ok(verified_vpn(interface, exit, api, false).await?.1) })
}

pub fn run_vpn(
    interface: &str,
    exit: ExitPolicy<'_>,
    api: Option<&Url>,
    interval: ExitCheckInterval,
    build_command: impl FnOnce(&Url) -> Result<Command>,
) -> Result<i32> {
    proxy::run_network(async {
        let (session, preflight) = verified_vpn(interface, exit, api, interval.is_auto()).await?;
        launch(session, preflight, exit.country, interval, build_command).await
    })
}

async fn launch(
    session: Session,
    preflight: Preflight,
    country: &str,
    interval: ExitCheckInterval,
    build_command: impl FnOnce(&Url) -> Result<Command>,
) -> Result<i32> {
    let command = build_command(&session.url)?;
    let interface = preflight
        .vpn_interface
        .map(|name| format!(" · VPN {name}"))
        .unwrap_or_default();
    notice::emit(
        Level::Exit,
        format_args!(
            "Exit check passed · {} ({country}){interface}",
            preflight.exit_ip
        ),
    );
    session
        .supervise(command, Duration::from_secs(interval.idle_seconds()))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    async fn headers(stream: &mut BufReader<TcpStream>) -> String {
        let mut headers = String::new();
        loop {
            let mut line = String::new();
            assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
            headers.push_str(&line);
            if line == "\r\n" {
                return headers;
            }
        }
    }

    async fn request(
        local: &Url,
        method: &str,
        target: &str,
        auth: Option<&str>,
    ) -> BufReader<TcpStream> {
        let mut stream = BufReader::new(
            TcpStream::connect((Ipv4Addr::LOCALHOST, local.port().unwrap()))
                .await
                .unwrap(),
        );
        let mut request = format!("{method} {target} HTTP/1.1\r\nHost: {target}\r\n");
        if let Some(auth) = auth {
            request.push_str(&format!("Proxy-Authorization: Basic {auth}\r\n"));
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await.unwrap();
        stream
    }

    fn token(url: &Url) -> String {
        STANDARD.encode(format!("{}:{}", url.username(), url.password().unwrap()))
    }

    #[tokio::test]
    async fn relay_auth_is_private_and_forwards_only_upstream_connect() {
        let upstream_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let proxy = Url::parse(&format!(
            "http://upstream:separate@{}",
            upstream_listener.local_addr().unwrap()
        ))
        .unwrap();
        let mut session = Session::start(&proxy, ExitPolicy::default(), false)
            .await
            .unwrap();
        let other = Session::start(&proxy, ExitPolicy::default(), false)
            .await
            .unwrap();
        let url = session.url.clone();
        let auth = token(&url);
        let unrelated_auth = token(&other.url);
        assert_ne!(url.port(), other.url.port());
        assert_ne!(auth, unrelated_auth);

        let upstream = tokio::spawn(async move {
            let (stream, _) = upstream_listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let head = headers(&mut stream).await;
            assert!(head.starts_with("CONNECT target.invalid:443 HTTP/1.1\r\n"));
            assert!(
                head.to_ascii_lowercase().contains(
                    &format!(
                        "Proxy-Authorization: Basic {}",
                        STANDARD.encode("upstream:separate")
                    )
                    .to_ascii_lowercase()
                )
            );
            assert!(!head.contains(&auth));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nearly")
                .await
                .unwrap();
            let mut ping = [0; 4];
            stream.read_exact(&mut ping).await.unwrap();
            assert_eq!(&ping, b"ping");
            stream.write_all(b"pong").await.unwrap();
            let mut byte = [0; 1];
            assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        });

        let exchange = async {
            let mut rejected =
                request(&url, "CONNECT", "target.invalid:443", Some(&unrelated_auth)).await;
            assert!(headers(&mut rejected).await.starts_with("HTTP/1.1 407"));
            let local_token = token(&url);
            let mut plain_http =
                request(&url, "GET", "http://target.invalid/", Some(&local_token)).await;
            assert!(headers(&mut plain_http).await.starts_with("HTTP/1.1 405"));

            let mut client =
                request(&url, "CONNECT", "target.invalid:443", Some(&local_token)).await;
            assert!(headers(&mut client).await.starts_with("HTTP/1.1 200"));
            let mut early = [0; 5];
            client.read_exact(&mut early).await.unwrap();
            assert_eq!(&early, b"early");
            client.write_all(b"ping").await.unwrap();
            let mut pong = [0; 4];
            client.read_exact(&mut pong).await.unwrap();
            assert_eq!(&pong, b"pong");
            client
        };

        let mut client = tokio::select! {
            error = &mut session.server => panic!("{error:#}"),
            stream = timeout(Duration::from_secs(4), exchange) => stream.unwrap(),
        };
        drop(session);
        timeout(Duration::from_secs(2), upstream)
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0; 1];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
    }
}
