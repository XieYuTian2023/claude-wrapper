use std::{fs, io::ErrorKind, net::TcpListener, os::unix::fs::PermissionsExt, process::Command};

const WRAPPER: &str = env!("CARGO_BIN_EXE_claude-wrapper");

#[test]
fn dry_run_reports_safe_configuration_without_running_client_or_probe() {
    let directory = tempfile::tempdir().unwrap();
    let profiles = directory.path().join("profiles");
    let create = Command::new(WRAPPER)
        .arg("--profiles-dir")
        .arg(&profiles)
        .args(["profile", "create", "preview", "--proxy-env", "LAB_PROXY"])
        .output()
        .unwrap();
    assert!(create.status.success(), "{create:?}");
    let stored_profile = fs::read(profiles.join("preview.toml")).unwrap();

    let client = directory.path().join("client");
    let marker = directory.path().join("client-ran");
    fs::write(&client, "#!/bin/sh\nprintf ran > \"$LAB_MARKER\"\n").unwrap();
    fs::set_permissions(&client, fs::Permissions::from_mode(0o700)).unwrap();

    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", proxy.local_addr().unwrap());
    let proxy_value = format!(
        "http://proxy-user:proxy-secret@{}",
        proxy.local_addr().unwrap()
    );
    let preview = |endpoint: &str| {
        Command::new(WRAPPER)
            .arg("--profiles-dir")
            .arg(&profiles)
            .args(["run", "preview", "--target"])
            .arg(&client)
            .args([
                "--identity",
                "env",
                "--network",
                "proxy-env",
                "--api-base-url",
                endpoint,
                "--dry-run",
            ])
            .env("LAB_PROXY", &proxy_value)
            .env("LAB_MARKER", &marker)
            .env("ANTHROPIC_API_KEY", "api-secret")
            .env("ANTHROPIC_AUTH_TOKEN", "auth-secret")
            .output()
            .unwrap()
    };
    let output = preview("https://api.example.test:8443/private-api-path");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stdout.contains("profile   preview"));
    assert!(stdout.contains(&format!(
        "{origin} (profile, environment variable LAB_PROXY)"
    )));
    assert!(stdout.contains("https://api.example.test:8443 (CLI override)"));
    assert!(stdout.contains("network and runtime checks not run"));
    assert!(stderr.contains("ANTHROPIC_API_KEY, ANTHROPIC_AUTH_TOKEN"));

    let rejected = preview("https://embedded-secret@api.example.test/");
    assert!(!rejected.status.success(), "{rejected:?}");
    let rejected_stderr = String::from_utf8(rejected.stderr).unwrap();
    let output = format!("{stdout}{stderr}{rejected_stderr}");
    for secret in [
        "proxy-user",
        "proxy-secret",
        "private-api-path",
        "api-secret",
        "auth-secret",
        "embedded-secret",
    ] {
        assert!(!output.contains(secret));
    }

    assert!(!marker.exists());
    assert_eq!(proxy.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    let files = fs::read_dir(&profiles)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(files, ["preview.toml"]);
    assert_eq!(
        fs::read(profiles.join("preview.toml")).unwrap(),
        stored_profile
    );
}
