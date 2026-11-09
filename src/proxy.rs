use std::{
    env,
    future::Future,
    net::IpAddr,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use reqwest::{Client, Proxy, StatusCode, Url, redirect::Policy};
use serde::Deserialize;

use crate::{exit_pin, profile::Profile};

const DEFAULT_GEOIP: &str = "https://api.country.is/";
const MAX_RESPONSE_BYTES: usize = 1024;

pub fn parse_proxy(value: &str, allow_auth: bool) -> Result<Url> {
    let url = Url::parse(value)
        .ok()
        .context("proxy must be an absolute HTTP(S) URL")?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host().is_some()
            && url.port_or_known_default().is_some_and(|port| port != 0)
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "proxy must be an HTTP(S) origin with a nonzero port, such as http://127.0.0.1:8080"
    );
    ensure!(
        allow_auth || (url.username().is_empty() && url.password().is_none()),
        "use proxy_env for proxy credentials"
    );
    Ok(url)
}

pub fn parse_geoip(value: &str) -> Result<Url> {
    let url = Url::parse(value)
        .ok()
        .context("geoip_url must be an absolute HTTPS URL")?;
    ensure!(
        url.scheme() == "https"
            && url.host().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none(),
        "geoip_url must use HTTPS without credentials or a fragment"
    );
    Ok(url)
}

pub fn endpoint(profile: &Profile) -> Result<Url> {
    if let Some(name) = &profile.proxy_env {
        let value =
            env::var(name).with_context(|| format!("set proxy environment variable {name}"))?;
        return parse_proxy(&value, true);
    }
    let value = profile
        .proxy_url
        .as_deref()
        .context("configure proxy_url or proxy_env")?;
    parse_proxy(value, false)
}

#[derive(Deserialize)]
struct GeoResponse {
    ip: IpAddr,
    country: String,
}

#[derive(Debug)]
pub(crate) struct UnexpectedExitCountry {
    pub observed: String,
    pub expected: String,
}

impl std::fmt::Display for UnexpectedExitCountry {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.observed == "CN" {
            write!(output, "proxy probe reported a mainland China exit (CN)")
        } else {
            write!(
                output,
                "GeoIP exit country mismatch: observed {}, expected {}",
                self.observed, self.expected
            )
        }
    }
}

impl std::error::Error for UnexpectedExitCountry {}

fn validate_response(body: &[u8], expected: &str) -> Result<IpAddr> {
    ensure!(
        body.len() <= MAX_RESPONSE_BYTES,
        "GeoIP response exceeds size limit"
    );
    let exit: GeoResponse = serde_json::from_slice(body)
        .map_err(|_| anyhow::anyhow!("GeoIP response must contain an IP and a country code"))?;
    ensure!(
        exit.country.len() == 2 && exit.country.bytes().all(|b| b.is_ascii_uppercase()),
        "GeoIP response returned an invalid country code"
    );
    if exit.country == "CN" || exit.country != expected {
        return Err(UnexpectedExitCountry {
            observed: exit.country,
            expected: expected.into(),
        }
        .into());
    }
    Ok(exit.ip)
}

fn verify_ip(observed: IpAddr, expected: IpAddr) -> Result<()> {
    if observed.to_canonical() != expected.to_canonical() {
        return Err(ExitIpError::Mismatch { observed, expected }.into());
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) enum ExitIpError {
    Mismatch { observed: IpAddr, expected: IpAddr },
    Unstable { first: IpAddr, observed: IpAddr },
}

impl std::fmt::Display for ExitIpError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mismatch { observed, expected } => write!(
                output,
                "GeoIP exit IP mismatch: observed {observed}, expected {expected}"
            ),
            Self::Unstable { first, observed } => write!(
                output,
                "automatic exit IP changed during learning: first {first}, then {observed}"
            ),
        }
    }
}

impl std::error::Error for ExitIpError {}

pub fn run_network<T>(future: impl Future<Output = Result<T>>) -> Result<T> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("could not initialize the network runtime")?;
    let result = runtime.block_on(future);
    // A cancelled system DNS lookup may still be running on a blocking worker.
    runtime.shutdown_background();
    result
}

pub struct Probe {
    client: Client,
    target: Url,
    country: String,
    expected_ip: Option<IpAddr>,
    auto_pin: Option<PathBuf>,
}

#[derive(Clone, Copy)]
pub struct ExitPolicy<'a> {
    pub geoip_url: Option<&'a str>,
    pub country: &'a str,
    pub expected_ip: Option<IpAddr>,
    pub auto_pin: Option<&'a Path>,
}

impl Default for ExitPolicy<'_> {
    fn default() -> Self {
        Self {
            geoip_url: None,
            country: "US",
            expected_ip: None,
            auto_pin: None,
        }
    }
}

impl Probe {
    pub fn new(proxy: &Url, exit: ExitPolicy<'_>) -> Result<Self> {
        Self::build(proxy, exit, Client::builder())
    }

    fn build(proxy: &Url, exit: ExitPolicy<'_>, client: reqwest::ClientBuilder) -> Result<Self> {
        let target = parse_geoip(exit.geoip_url.unwrap_or(DEFAULT_GEOIP))?;
        let proxy = Proxy::all(proxy.as_str())
            .map_err(|_| anyhow::anyhow!("invalid proxy configuration"))?;
        let client = client
            .no_proxy()
            .proxy(proxy)
            .redirect(Policy::none())
            // Each check must exercise a fresh proxy connection.
            .pool_max_idle_per_host(0)
            .http1_only()
            .timeout(Duration::from_secs(8))
            .build()
            .map_err(|_| anyhow::anyhow!("could not initialize proxy probe"))?;
        Ok(Self {
            client,
            target,
            country: exit.country.into(),
            expected_ip: match exit.auto_pin {
                Some(path) => exit_pin::read(path)?,
                None => exit.expected_ip,
            },
            auto_pin: exit.auto_pin.map(Path::to_path_buf),
        })
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn with_test_ca(proxy: &Url, exit: ExitPolicy<'_>, pem: &[u8]) -> Result<Self> {
        let ca = reqwest::Certificate::from_pem(pem)?;
        Self::build(proxy, exit, Client::builder().add_root_certificate(ca))
    }

    pub async fn check(&self) -> Result<IpAddr> {
        let mut response = self
            .client
            .get(self.target.clone())
            .header(reqwest::header::CACHE_CONTROL, "no-cache, no-store")
            .header(reqwest::header::PRAGMA, "no-cache")
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    anyhow::anyhow!("proxy probe timed out")
                } else {
                    anyhow::anyhow!(
                        "proxy probe failed to reach the GeoIP service through the configured proxy"
                    )
                }
            })?;
        ensure!(
            response.status().is_success(),
            "GeoIP service returned HTTP {}",
            response.status()
        );
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| anyhow::anyhow!("could not read the GeoIP response"))?
        {
            ensure!(
                chunk.len() <= MAX_RESPONSE_BYTES - body.len(),
                "GeoIP response exceeds size limit"
            );
            body.extend_from_slice(&chunk);
        }
        let actual = validate_response(&body, &self.country)?;
        if let Some(expected) = self.expected_ip {
            verify_ip(actual, expected)?;
        }
        Ok(actual)
    }

    pub async fn learn_ip(&mut self, first: IpAddr) -> Result<()> {
        let Some(path) = self.auto_pin.as_deref() else {
            return Ok(());
        };
        if self.expected_ip.is_some() {
            return Ok(());
        }
        let first = first.to_canonical();
        for _ in 1..exit_pin::SAMPLES {
            let observed = self.check().await?.to_canonical();
            if first != observed {
                return Err(ExitIpError::Unstable { first, observed }.into());
            }
        }
        let pinned = exit_pin::establish(path, first)?;
        verify_ip(first, pinned)?;
        self.expected_ip = Some(pinned);
        eprintln!(
            "claude-wrapper: automatic exit pinned to {pinned} after {} matching probes",
            exit_pin::SAMPLES
        );
        Ok(())
    }

    pub(crate) async fn check_api(&self, target: &Url) -> Result<StatusCode> {
        let response = self.client.head(target.clone()).send().await.map_err(|_| {
            anyhow::anyhow!("Claude API HTTPS probe failed through the selected route")
        })?;
        Ok(response.status())
    }
}

pub fn check(proxy: &Url, exit: ExitPolicy<'_>) -> Result<IpAddr> {
    run_network(async {
        let mut probe = Probe::new(proxy, exit)?;
        let ip = probe.check().await?;
        probe.learn_ip(ip).await?;
        Ok(ip)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_us_with_a_valid_ip_passes() {
        assert_eq!(
            validate_response(br#"{"ip":"2606:4700::1111","country":"US"}"#, "US").unwrap(),
            "2606:4700::1111".parse::<IpAddr>().unwrap()
        );
        for body in [
            r#"{"ip":"1.1.1.1","country":"CN"}"#,
            r#"{"ip":"1.1.1.1","country":"CA"}"#,
            r#"{"ip":"bad","country":"US"}"#,
            r#"{"ip":"1.1.1.1","country":null}"#,
            r#"{"ip":"1.1.1.1","country":"unknown"}"#,
        ] {
            assert!(validate_response(body.as_bytes(), "US").is_err(), "{body}");
        }
        assert!(validate_response(&[b' '; 1025], "US").is_err());
    }

    #[test]
    fn configured_country_accepts_its_own_exit_but_cn_is_always_blocked() {
        let jp = br#"{"ip":"203.0.113.1","country":"JP"}"#;
        let cn = br#"{"ip":"203.0.113.1","country":"CN"}"#;
        assert_eq!(
            validate_response(jp, "JP").unwrap(),
            "203.0.113.1".parse::<IpAddr>().unwrap()
        );
        assert!(
            validate_response(jp, "CA")
                .unwrap_err()
                .is::<UnexpectedExitCountry>()
        );
        assert!(
            validate_response(cn, "CN")
                .unwrap_err()
                .is::<UnexpectedExitCountry>()
        );
    }

    #[test]
    fn proxy_urls_are_origins_and_secrets_require_env() {
        for invalid in [
            "socks5://localhost:1080",
            "https://host:0",
            "http://host/proxy",
            "http://user:pw@host",
        ] {
            assert!(parse_proxy(invalid, false).is_err(), "{invalid}");
        }
        assert!(parse_proxy("https://user:pw@host:8443", true).is_ok());
        assert!(parse_proxy("http://[::1]:8080", false).is_ok());
    }
}
