//! Local TLS fixtures use a public test key and process-local trust anchors.
use super::*;
use std::{
    fs,
    path::Path,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};

use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    task::JoinHandle,
};
use tokio_native_tls::TlsAcceptor;

const CA_CERT: &[u8] = include_bytes!("../../tests/fixtures/geoip-test-ca.pem");
const CA_KEY: &[u8] = include_bytes!("../../tests/fixtures/geoip-test-ca-key.pem");
const GEOIP_URL: &str = "https://geoip.test/";
const TEST_LIMIT: Duration = Duration::from_secs(5);
const CHECK_INTERVAL: Duration = Duration::from_millis(40);
static SUPERVISION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct LocalProxy {
    url: Url,
    report_cn: Arc<AtomicBool>,
    report_new_ip: Arc<AtomicBool>,
    probe_count: Arc<AtomicUsize>,
    server: JoinHandle<()>,
}

impl LocalProxy {
    async fn start() -> Self {
        Self::start_in("US").await
    }

    async fn start_in(region: &'static str) -> Self {
        let tls = test_acceptor();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let report_cn = Arc::new(AtomicBool::new(false));
        let probe_count = Arc::new(AtomicUsize::new(0));
        let country = Arc::clone(&report_cn);
        let report_new_ip = Arc::new(AtomicBool::new(false));
        let new_ip = Arc::clone(&report_new_ip);
        let probes = Arc::clone(&probe_count);
        let server = tokio::spawn(async move {
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    completed = connections.join_next(), if !connections.is_empty() => {
                        completed.unwrap().unwrap();
                    }
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        let tls = tls.clone();
                        let country = Arc::clone(&country);
                        let new_ip = Arc::clone(&new_ip);
                        let probes = Arc::clone(&probes);
                        connections.spawn(async move {
                            let mut stream = BufReader::new(stream);
                            let request = head(&mut stream).await;
                            let target = request.lines().next().unwrap().to_owned();
                            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                                .await.unwrap();
                            if target == "CONNECT geoip.test:444 HTTP/1.1" {
                                return;
                            }
                            if target == "CONNECT geoip.test:443 HTTP/1.1" {
                                let mut stream = BufReader::new(tls.accept(stream).await.unwrap());
                                let request = head(&mut stream).await;
                                if request.starts_with("HEAD /v1/models HTTP/1.1\r\n") {
                                    assert!(!request.to_ascii_lowercase().contains("authorization:"));
                                    stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                                    stream.flush().await.unwrap();
                                    return;
                                }
                                assert!(request.starts_with("GET / HTTP/1.1\r\n"), "{request}");
                                probes.fetch_add(1, Ordering::SeqCst);
                                let country = if country.load(Ordering::SeqCst) { "CN" } else { region };
                                let ip = if new_ip.load(Ordering::SeqCst) { "8.8.4.4" } else { "8.8.8.8" };
                                let body = format!(r#"{{"ip":"{ip}","country":"{country}"}}"#);
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                    body.len()
                                );
                                stream.write_all(response.as_bytes()).await.unwrap();
                                stream.flush().await.unwrap();
                            } else {
                                assert_eq!(target, "CONNECT stream.test:443 HTTP/1.1");
                                stream.write_all(b"ready").await.unwrap();
                                stream.flush().await.unwrap();
                                let mut byte = [0; 1];
                                assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
                            }
                        });
                    }
                }
            }
        });
        Self {
            url,
            report_cn,
            report_new_ip,
            probe_count,
            server,
        }
    }

    async fn session(&self) -> Session {
        self.session_with_expected_ip(None).await
    }

    async fn session_with_expected_ip(&self, expected_ip: Option<IpAddr>) -> Session {
        let exit = ExitPolicy {
            geoip_url: Some(GEOIP_URL),
            expected_ip,
            ..ExitPolicy::default()
        };
        let mut session = self.open_session(exit).await;
        assert_eq!(
            timeout(TEST_LIMIT, session.check()).await.unwrap().unwrap(),
            "8.8.8.8".parse::<IpAddr>().unwrap()
        );
        assert_eq!(self.probe_count.load(Ordering::SeqCst), 1);
        session
    }

    async fn open_session(&self, exit: ExitPolicy<'_>) -> Session {
        let mut session = Session::start(&self.url, exit, false).await.unwrap();
        session.probe = Probe::with_test_ca(&session.probe_url, exit, CA_CERT).unwrap();
        session
    }
}

#[tokio::test]
async fn non_us_policy_checks_the_country_and_manually_expected_ip() {
    let proxy = LocalProxy::start_in("JP").await;
    let mut session = proxy
        .open_session(ExitPolicy {
            geoip_url: Some(GEOIP_URL),
            country: "JP",
            expected_ip: Some("8.8.8.8".parse().unwrap()),
            ..ExitPolicy::default()
        })
        .await;
    assert_eq!(
        session.preflight(None).await.unwrap().exit_ip,
        "8.8.8.8".parse::<IpAddr>().unwrap()
    );
    proxy.report_new_ip.store(true, Ordering::SeqCst);
    assert!(
        session
            .preflight(None)
            .await
            .unwrap_err()
            .is::<proxy::ExitIpError>()
    );
}

#[tokio::test]
async fn adaptive_checks_ignore_probe_traffic_and_accelerate_on_a_burst() {
    let proxy = LocalProxy::start().await;
    let exit = ExitPolicy {
        geoip_url: Some(GEOIP_URL),
        ..ExitPolicy::default()
    };
    let mut session = Session::start(&proxy.url, exit, true).await.unwrap();
    session.probe = Probe::with_test_ca(&session.probe_url, exit, CA_CERT).unwrap();
    let api = Url::parse("https://geoip.test/v1/models").unwrap();
    session.preflight(Some(&api)).await.unwrap();
    let activity = session.activity.as_deref().unwrap();
    let sample = activity.take();
    assert_eq!(sample.connections, 0);
    assert_eq!(sample.bytes, 0);

    proxy.report_cn.store(true, Ordering::SeqCst);
    let requests = async {
        for _ in 0..3 {
            drop(open_stream(&session.url).await);
        }
    };
    let check = async {
        tokio::select! {
            failure = &mut session.server => failure,
            failure = monitor(&session.probe, Duration::from_secs(30), Some(activity)) => failure,
        }
    };
    let (_, failure) = timeout(Duration::from_secs(10), async {
        tokio::join!(requests, check)
    })
    .await
    .unwrap();
    assert!(failure.is::<proxy::UnexpectedExitCountry>());
    assert_eq!(proxy.probe_count.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn auto_exit_pin_learns_three_fresh_results_and_reuses_pin_until_reset() {
    let proxy = LocalProxy::start().await;
    let root = tempfile::tempdir().unwrap();
    let pin_path = root.path().join(".exit-pin-lab");
    let policy = ExitPolicy {
        geoip_url: Some(GEOIP_URL),
        auto_pin: Some(&pin_path),
        ..ExitPolicy::default()
    };
    let mut session = proxy.open_session(policy).await;
    let ip = session.check().await.unwrap();
    proxy.report_new_ip.store(true, Ordering::SeqCst);
    let result = tokio::select! {
        failure = &mut session.server => Err(failure),
        result = session.probe.learn_ip(ip) => result,
    };
    assert!(matches!(
        result.unwrap_err().downcast_ref::<proxy::ExitIpError>(),
        Some(proxy::ExitIpError::Unstable { .. })
    ));
    assert!(!pin_path.exists());
    proxy.report_new_ip.store(false, Ordering::SeqCst);

    let before = proxy.probe_count.load(Ordering::SeqCst);
    assert_eq!(session.preflight(None).await.unwrap().exit_ip, ip);
    assert_eq!(
        proxy.probe_count.load(Ordering::SeqCst) - before,
        crate::exit_pin::SAMPLES
    );
    assert_eq!(crate::exit_pin::read(&pin_path).unwrap(), Some(ip));

    let mut restarted = proxy.open_session(policy).await;
    proxy.report_new_ip.store(true, Ordering::SeqCst);
    assert!(matches!(
        restarted
            .preflight(None)
            .await
            .unwrap_err()
            .downcast_ref::<proxy::ExitIpError>(),
        Some(proxy::ExitIpError::Mismatch { .. })
    ));
    assert_eq!(crate::exit_pin::read(&pin_path).unwrap(), Some(ip));

    fs::write(
        root.path().join("lab.toml"),
        "timezone = \"America/Chicago\"\nlocale = \"en_US.UTF-8\"\nexpected_exit_ip = \"auto\"\n",
    )
    .unwrap();
    crate::profile::reset_exit_pin(root.path(), "lab").unwrap();
    let mut reset = proxy.open_session(policy).await;
    let new_ip = reset.preflight(None).await.unwrap().exit_ip;
    assert_ne!(new_ip, ip);
    assert_eq!(crate::exit_pin::read(&pin_path).unwrap(), Some(new_ip));
    assert_eq!(crate::journal::read(root.path()).unwrap().len(), 3);
}

#[tokio::test]
async fn claude_preflight_requires_api_transport_after_us_exit() {
    let proxy = LocalProxy::start().await;
    let mut session = proxy.session().await;
    let reachable = Url::parse("https://geoip.test/v1/models").unwrap();
    let reset = Url::parse("https://geoip.test:444/v1/models").unwrap();
    let checked = session.preflight(Some(&reachable)).await.unwrap();
    assert_eq!(checked.api_status, Some(StatusCode::METHOD_NOT_ALLOWED));
    let error = session.preflight(Some(&reset)).await.unwrap_err();
    assert!(error.to_string().contains("Claude API HTTPS probe failed"));
    assert_eq!(proxy.probe_count.load(Ordering::SeqCst), 3);
}

fn test_acceptor() -> TlsAcceptor {
    let directory = tempfile::tempdir().unwrap();
    let ca_cert = directory.path().join("ca.pem");
    let ca_key = directory.path().join("ca-key.pem");
    let key = directory.path().join("server-key.pem");
    let pkcs8_key = directory.path().join("server-pkcs8.pem");
    let csr = directory.path().join("server.csr");
    let cert = directory.path().join("server.pem");
    let extensions = directory.path().join("extensions.cnf");
    fs::write(&ca_cert, CA_CERT).unwrap();
    fs::write(&ca_key, CA_KEY).unwrap();
    fs::write(
        &extensions,
        "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:geoip.test\n",
    )
    .unwrap();
    // Apple limits leaf lifetimes. Generate a short-lived certificate for each test run.
    let output = Command::new("/usr/bin/openssl")
        .args([
            "req",
            "-new",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-subj",
            "/CN=geoip.test",
            "-keyout",
        ])
        .arg(&key)
        .arg("-out")
        .arg(&csr)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("/usr/bin/openssl")
        .args(["x509", "-req", "-in"])
        .arg(&csr)
        .arg("-CA")
        .arg(&ca_cert)
        .arg("-CAkey")
        .arg(&ca_key)
        .args(["-set_serial", "1", "-days", "2", "-extfile"])
        .arg(&extensions)
        .arg("-out")
        .arg(&cert)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new("/usr/bin/openssl")
        .args(["pkcs8", "-topk8", "-nocrypt", "-in"])
        .arg(&key)
        .arg("-out")
        .arg(&pkcs8_key)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let identity =
        native_tls::Identity::from_pkcs8(&fs::read(cert).unwrap(), &fs::read(pkcs8_key).unwrap())
            .unwrap();
    TlsAcceptor::from(native_tls::TlsAcceptor::new(identity).unwrap())
}

impl Drop for LocalProxy {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn head(stream: &mut (impl AsyncBufRead + Unpin)) -> String {
    let mut head = String::new();
    loop {
        let mut line = String::new();
        assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
        head.push_str(&line);
        if line == "\r\n" {
            return head;
        }
    }
}

async fn open_stream(url: &Url) -> BufReader<TcpStream> {
    let mut stream = BufReader::new(
        TcpStream::connect((Ipv4Addr::LOCALHOST, url.port().unwrap()))
            .await
            .unwrap(),
    );
    let auth = STANDARD.encode(format!("{}:{}", url.username(), url.password().unwrap()));
    let request = format!(
        "CONNECT stream.test:443 HTTP/1.1\r\nHost: stream.test:443\r\nProxy-Authorization: Basic {auth}\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    assert!(head(&mut stream).await.starts_with("HTTP/1.1 200"));
    let mut ready = [0; 5];
    stream.read_exact(&mut ready).await.unwrap();
    assert_eq!(&ready, b"ready");
    stream
}

async fn child_pid(path: &Path) -> libc::pid_t {
    loop {
        if let Ok(pid) = fs::read_to_string(path)
            && let Ok(pid) = pid.trim().parse()
        {
            return pid;
        }
        sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn verified_tls_probe_launches_a_normal_child_and_preserves_exit_code() {
    let _supervision = SUPERVISION_LOCK.lock().await;
    let proxy = LocalProxy::start().await;
    let session = proxy.session().await;
    let relay_address = (Ipv4Addr::LOCALHOST, session.url.port().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let marker = directory.path().join("native-file.txt");
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "printf native > \"$1\"; exit 37", "fixture"]);
    command.arg(&marker);
    let code = timeout(TEST_LIMIT, session.supervise(command, CHECK_INTERVAL))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(code, 37);
    assert_eq!(fs::read_to_string(&marker).unwrap(), "native");
    assert!(TcpStream::connect(relay_address).await.is_err());
}

#[tokio::test]
async fn runtime_cn_result_closes_listener_and_live_tunnel_and_reaps_child() {
    assert_runtime_exit_change_stops_session(false).await;
}

#[tokio::test]
async fn runtime_pinned_ip_change_in_same_country_stops_session() {
    assert_runtime_exit_change_stops_session(true).await;
}

async fn assert_runtime_exit_change_stops_session(change_ip: bool) {
    let _supervision = SUPERVISION_LOCK.lock().await;
    let proxy = LocalProxy::start().await;
    let session = proxy
        .session_with_expected_ip(change_ip.then(|| "8.8.8.8".parse().unwrap()))
        .await;
    let relay_url = session.url.clone();
    let relay_address = (Ipv4Addr::LOCALHOST, relay_url.port().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("child.pid");
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "echo $$ > \"$1\"; exec /bin/sleep 30", "fixture"]);
    command.arg(&pid_file);
    let inspect = async {
        let pid = child_pid(&pid_file).await;
        let mut stream = open_stream(&relay_url).await;
        if change_ip {
            proxy.report_new_ip.store(true, Ordering::SeqCst);
        } else {
            proxy.report_cn.store(true, Ordering::SeqCst);
        }
        let mut byte = [0; 1];
        assert_eq!(stream.read(&mut byte).await.unwrap(), 0);
        pid
    };
    let (outcome, pid) = timeout(TEST_LIMIT, async {
        tokio::join!(session.supervise(command, CHECK_INTERVAL), inspect)
    })
    .await
    .unwrap();
    let error = outcome.unwrap_err();
    if change_ip {
        assert!(error.is::<proxy::ExitIpError>(), "{error:#}");
    } else {
        assert!(error.is::<proxy::UnexpectedExitCountry>(), "{error:#}");
    }
    assert!(proxy.probe_count.load(Ordering::SeqCst) >= 2);
    assert!(TcpStream::connect(relay_address).await.is_err());
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[tokio::test]
async fn targeted_interrupt_reaches_child_and_closes_relay() {
    let _supervision = SUPERVISION_LOCK.lock().await;
    let proxy = LocalProxy::start().await;
    let session = proxy.session().await;
    let relay_address = (Ipv4Addr::LOCALHOST, session.url.port().unwrap());
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("interrupt-child.pid");
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "echo $$ > \"$1\"; exec /bin/sleep 30", "fixture"]);
    command.arg(&pid_file);
    let interrupt = async {
        let pid = child_pid(&pid_file).await;
        assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGINT) }, 0);
        pid
    };
    let (outcome, pid) = timeout(TEST_LIMIT, async {
        tokio::join!(session.supervise(command, CHECK_INTERVAL), interrupt)
    })
    .await
    .unwrap();
    assert_eq!(outcome.unwrap(), 130);
    assert!(TcpStream::connect(relay_address).await.is_err());
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
}

#[tokio::test]
async fn exiting_leader_cannot_leave_an_ordinary_descendant_alive() {
    let _supervision = SUPERVISION_LOCK.lock().await;
    let proxy = LocalProxy::start().await;
    let session = proxy.session().await;
    let directory = tempfile::tempdir().unwrap();
    let descendant_file = directory.path().join("descendant.pid");
    let mut command = Command::new("/bin/sh");
    command.args(["-c", "sleep 30 & echo $! > \"$1\"; exit 37", "fixture"]);
    command.arg(&descendant_file);
    let status = timeout(TEST_LIMIT, session.supervise(command, CHECK_INTERVAL))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status, 37);
    let pid = child_pid(&descendant_file).await;
    assert!(
        process_has_exited(pid),
        "ordinary descendant {pid} survived leader exit"
    );
}

fn process_has_exited(pid: libc::pid_t) -> bool {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            std::mem::size_of_val(&info) as i32,
        )
    };
    result <= 0 || info.pbi_status == libc::SZOMB as u32
}

#[tokio::test]
async fn runtime_failure_stops_a_term_resistant_descendant() {
    let _supervision = SUPERVISION_LOCK.lock().await;
    let proxy = LocalProxy::start().await;
    let session = proxy.session().await;
    let directory = tempfile::tempdir().unwrap();
    let pid_file = directory.path().join("resistant.pid");
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "trap '' TERM; /bin/sh -c 'echo $$ > \"$1\"; exec sleep 30' fixture \"$1\" & wait",
        "fixture",
    ]);
    command.arg(&pid_file);
    let inspect = async {
        let pid = child_pid(&pid_file).await;
        proxy.report_cn.store(true, Ordering::SeqCst);
        pid
    };
    let (status, pid) = timeout(TEST_LIMIT, async {
        tokio::join!(session.supervise(command, CHECK_INTERVAL), inspect)
    })
    .await
    .unwrap();
    assert!(status.is_err());
    assert!(
        process_has_exited(pid),
        "TERM-resistant descendant {pid} survived health failure"
    );
}
