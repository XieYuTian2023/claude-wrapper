use std::{
    io::{Read, Write},
    net::TcpListener,
    path::Path,
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

const WRAPPER: &str = env!("CARGO_BIN_EXE_claude-wrapper");

fn cli(dir: &Path) -> Command {
    let mut command = Command::new(WRAPPER);
    command.arg("--profiles-dir").arg(dir);
    command
}

fn create(dir: &Path, proxy_flag: &str, proxy: &str) {
    let output = cli(dir)
        .args(["profile", "create", "lab-a", proxy_flag, proxy])
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
}

fn run(dir: &Path) -> Command {
    let mut command = cli(dir);
    command.args([
        "run",
        "lab-a",
        "--target",
        WRAPPER,
        "--identity",
        "env",
        "--network",
        "proxy-env",
    ]);
    command
}

fn output_text(output: &Output) -> (&str, &str) {
    (
        std::str::from_utf8(&output.stdout).unwrap(),
        std::str::from_utf8(&output.stderr).unwrap(),
    )
}

#[test]
fn profile_copy_does_not_overwrite_and_dry_run_redacts_credentials() {
    let dir = tempfile::tempdir().unwrap();
    create(dir.path(), "--proxy-env", "LAB_PROXY_SECRET");
    let copy = || {
        cli(dir.path())
            .args(["profile", "copy", "lab-a", "lab-b"])
            .output()
            .unwrap()
    };
    assert!(copy().status.success());
    assert!(!copy().status.success());

    let output = run(dir.path())
        .args([
            "--dry-run",
            "--timezone",
            "America/Chicago",
            "--",
            "--version",
        ])
        .env(
            "LAB_PROXY_SECRET",
            "https://login:secret-value@example.invalid:8443",
        )
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&output);
    assert!(output.status.success(), "{stderr}");
    assert!(!stdout.contains("hostname") && !stdout.contains("username"));
    assert!(stdout.contains("America/Chicago"));
    assert!(stdout.contains("https://example.invalid:8443"));
    assert!(!stdout.contains("secret-value"));
    assert!(!stderr.contains("secret-value"));
    assert!(stdout.contains("direct sockets allowed"));
    assert!(!stdout.contains("claude-wrapper 0.1"));

    let list = cli(dir.path()).args(["profile", "list"]).output().unwrap();
    assert_eq!(
        output_text(&list).0.lines().collect::<Vec<_>>(),
        ["lab-a", "lab-b"]
    );
    assert!(
        cli(dir.path())
            .args(["profile", "delete", "lab-b"])
            .status()
            .unwrap()
            .success()
    );
    assert!(!dir.path().join("lab-b.toml").exists());
}

#[test]
fn deleted_profile_state_cannot_be_assigned_to_a_new_identity() {
    let dir = tempfile::tempdir().unwrap();
    create(dir.path(), "--proxy", "http://127.0.0.1:8080");
    let client = dir.path().join("clients/lab-a");
    std::fs::create_dir_all(&client).unwrap();
    let retained = br#"{"userID":"previous-identity","testHistory":"retain me"}"#;
    std::fs::write(client.join(".claude.json"), retained).unwrap();
    let deleted = cli(dir.path())
        .args(["profile", "delete", "lab-a"])
        .output()
        .unwrap();
    assert!(deleted.status.success());
    assert_eq!(
        std::fs::read(client.join(".claude.json")).unwrap(),
        retained
    );
    let recreated = cli(dir.path())
        .args([
            "profile",
            "create",
            "lab-a",
            "--proxy",
            "http://127.0.0.1:8080",
        ])
        .output()
        .unwrap();
    assert!(!recreated.status.success());
    assert!(output_text(&recreated).1.contains("retained Claude state"));
    assert!(!dir.path().join("lab-a.toml").exists());
    let fresh = cli(dir.path())
        .args([
            "profile",
            "create",
            "lab-b",
            "--proxy",
            "http://127.0.0.1:8080",
        ])
        .output()
        .unwrap();
    assert!(fresh.status.success());
    let copied = cli(dir.path())
        .args(["profile", "copy", "lab-b", "lab-a"])
        .output()
        .unwrap();
    assert!(!copied.status.success());
    assert_eq!(
        std::fs::read(client.join(".claude.json")).unwrap(),
        retained
    );
}

#[test]
fn failed_connect_probe_prevents_target_start_even_with_inherited_no_proxy() {
    let dir = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    create(dir.path(), "--proxy", &format!("http://{addr}"));
    let child = run(dir.path())
        .args(["--", "--version"])
        .env("NO_PROXY", "*")
        .env("no_proxy", "*")
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match listener.accept() {
            Ok((stream, _)) => break stream,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("configured proxy received no connection: {error}"),
        }
    };
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = Vec::new();
    while request.len() < 4096 && !request.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        request.push(byte[0]);
    }
    assert!(request.starts_with(b"CONNECT api.country.is:443 HTTP/1.1\r\n"));
    stream
        .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
        .unwrap();
    drop(stream);
    let output = child.wait_with_output().unwrap();
    let (stdout, stderr) = output_text(&output);
    assert!(!output.status.success());
    assert!(stdout.is_empty(), "unexpected target output {stdout}");
    assert!(stderr.contains("proxy probe failed"), "{stderr}");
    assert!(
        stderr
            .lines()
            .any(|line| line.starts_with("[Wrapper/错误]: ")),
        "{stderr}"
    );
    assert!(!stderr.contains('\x1b'), "{stderr}");
}

#[cfg(target_os = "macos")]
#[test]
fn vpn_source_can_switch_to_proxy_and_invalid_mixed_modes_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let created = cli(dir.path())
        .args([
            "profile",
            "create",
            "vpn-a",
            "--vpn-interface",
            "auto",
            "--identity",
            "env",
        ])
        .output()
        .unwrap();
    assert!(created.status.success(), "{created:?}");
    let stored = std::fs::read(dir.path().join("vpn-a.toml")).unwrap();
    let plan = cli(dir.path())
        .args([
            "run",
            "vpn-a",
            "--target",
            WRAPPER,
            "--socket-guard",
            WRAPPER,
            "--proxy",
            "http://127.0.0.1:8080",
            "--dry-run",
        ])
        .output()
        .unwrap();
    let (stdout, stderr) = output_text(&plan);
    assert!(plan.status.success(), "{stderr}");
    assert!(stdout.contains("proxy     http://127.0.0.1:8080"));
    assert!(stdout.contains("per-launch CONNECT relay"));
    assert_eq!(
        std::fs::read(dir.path().join("vpn-a.toml")).unwrap(),
        stored
    );

    let invalid = cli(dir.path())
        .args([
            "profile",
            "create",
            "invalid",
            "--vpn-interface",
            "auto",
            "--network",
            "proxy-env",
        ])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(!dir.path().join("invalid.toml").exists());
}
