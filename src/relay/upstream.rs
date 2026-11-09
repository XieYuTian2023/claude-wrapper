use std::{net::SocketAddr, time::Duration};

use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use http::{HeaderValue, StatusCode, uri::Authority};
use percent_encoding::percent_decode_str;
use reqwest::Url;
use tokio::{
    io::{
        AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt,
        BufReader,
    },
    net::{TcpStream, lookup_host},
    time::timeout,
};
use tokio_native_tls::TlsConnector;

const TIMEOUT: Duration = Duration::from_secs(8);
const MAX_RESPONSE_BYTES: u64 = 16 * 1024;
const MAX_RESPONSE_HEADERS: usize = 64;
const MAX_INFORMATIONAL_RESPONSES: usize = 8;

trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyStream for T {}

pub(super) struct Upstream {
    address: SocketAddr,
    tls: Option<(String, TlsConnector)>,
    authorization: Option<HeaderValue>,
}

impl Upstream {
    pub(super) async fn resolve(proxy: &Url) -> Result<Self> {
        let host = proxy.host_str().context("missing upstream proxy host")?;
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let port = proxy
            .port_or_known_default()
            .filter(|port| *port != 0)
            .context("invalid upstream proxy port")?;
        let tls = match proxy.scheme() {
            "http" => None,
            "https" => {
                let connector = native_tls::TlsConnector::new()
                    .map_err(|_| anyhow!("could not initialize TLS for the upstream proxy"))?;
                Some((host.to_owned(), TlsConnector::from(connector)))
            }
            _ => return Err(anyhow!("upstream proxy must use HTTP or HTTPS")),
        };
        let authorization = authorization(proxy)?;
        let mut addresses = timeout(TIMEOUT, lookup_host((host, port)))
            .await
            .map_err(|_| anyhow!("upstream proxy DNS lookup timed out"))?
            .map_err(|_| anyhow!("could not resolve the upstream proxy host"))?;
        let address = addresses
            .next()
            .context("upstream proxy host resolved to no addresses")?;
        Ok(Self {
            address,
            tls,
            authorization,
        })
    }

    pub(super) async fn connect(
        &self,
        authority: &Authority,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + use<>> {
        ensure!(
            !authority.host().is_empty()
                && !authority.as_str().contains('@')
                && authority.port_u16().is_some_and(|port| port != 0),
            "CONNECT requires a host and a nonzero port"
        );
        timeout(TIMEOUT, self.open_tunnel(authority))
            .await
            .map_err(|_| anyhow!("upstream proxy CONNECT timed out"))?
    }

    async fn open_tunnel(&self, authority: &Authority) -> Result<BufReader<Box<dyn ProxyStream>>> {
        let stream = TcpStream::connect(self.address)
            .await
            .map_err(|_| anyhow!("could not connect to the upstream proxy"))?;
        stream.set_nodelay(true)?;
        let stream: Box<dyn ProxyStream> = match &self.tls {
            Some((host, connector)) => {
                let stream = connector
                    .connect(host, stream)
                    .await
                    .map_err(|_| anyhow!("TLS handshake with the upstream proxy failed"))?;
                Box::new(stream)
            }
            None => Box::new(stream),
        };
        let mut stream = BufReader::new(stream);
        let request = connect_request(authority, self.authorization.as_ref());
        stream.write_all(&request).await?;
        stream.flush().await?;
        read_connect_response(&mut stream).await?;
        // Keep the reader intact so any bytes following the response headers remain available.
        Ok(stream)
    }
}

fn authorization(proxy: &Url) -> Result<Option<HeaderValue>> {
    if proxy.username().is_empty() && proxy.password().is_none() {
        return Ok(None);
    }
    let user = percent_decode_str(proxy.username())
        .decode_utf8()
        .map_err(|_| anyhow!("upstream proxy username must be UTF-8"))?;
    let password = percent_decode_str(proxy.password().unwrap_or(""))
        .decode_utf8()
        .map_err(|_| anyhow!("upstream proxy password must be UTF-8"))?;
    ensure!(
        !user.contains(':')
            && !user
                .bytes()
                .chain(password.bytes())
                .any(|b| b.is_ascii_control()),
        "upstream proxy credentials contain invalid characters"
    );
    let encoded = STANDARD.encode(format!("{user}:{password}"));
    let mut value = HeaderValue::from_str(&format!("Basic {encoded}"))
        .map_err(|_| anyhow!("could not encode upstream proxy credentials"))?;
    value.set_sensitive(true);
    Ok(Some(value))
}

fn connect_request(authority: &Authority, authorization: Option<&HeaderValue>) -> Vec<u8> {
    let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n").into_bytes();
    if let Some(authorization) = authorization {
        request.extend_from_slice(b"Proxy-Authorization: ");
        request.extend_from_slice(authorization.as_bytes());
        request.extend_from_slice(b"\r\n");
    }
    request.extend_from_slice(b"\r\n");
    request
}

async fn read_connect_response(stream: &mut (impl AsyncBufRead + Unpin)) -> Result<()> {
    let mut bounded = stream.take(MAX_RESPONSE_BYTES);
    let mut head = Vec::new();
    for _ in 0..=MAX_INFORMATIONAL_RESPONSES {
        head.clear();
        loop {
            let line_start = head.len();
            bounded.read_until(b'\n', &mut head).await?;
            let line = &head[line_start..];
            ensure!(
                line.ends_with(b"\r\n"),
                "upstream proxy response headers are incomplete, malformed, or too large"
            );
            if line == b"\r\n" {
                break;
            }
        }
        let mut headers = [httparse::EMPTY_HEADER; MAX_RESPONSE_HEADERS];
        let mut response = httparse::Response::new(&mut headers);
        let parsed = response
            .parse(&head)
            .map_err(|_| anyhow!("invalid upstream proxy response headers"))?;
        ensure!(
            parsed == httparse::Status::Complete(head.len()),
            "invalid upstream proxy response headers"
        );
        let status = StatusCode::from_u16(response.code.context("missing upstream proxy status")?)
            .map_err(|_| anyhow!("invalid upstream proxy status"))?;
        if status.is_informational() && status != StatusCode::SWITCHING_PROTOCOLS {
            continue;
        }
        ensure!(
            status.is_success(),
            "upstream proxy rejected CONNECT with status {}",
            status.as_u16()
        );
        return Ok(());
    }
    Err(anyhow!(
        "upstream proxy sent too many informational responses"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    async fn request_headers(stream: &mut TcpStream) -> Vec<String> {
        let mut reader = BufReader::new(stream);
        let mut lines = Vec::new();
        loop {
            let mut line = String::new();
            assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
            if line == "\r\n" {
                return lines;
            }
            lines.push(line);
        }
    }

    #[tokio::test]
    async fn authenticates_upstream_and_preserves_early_tunnel_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://up%40stream:p%3Aa%20ss@{}",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let upstream = Upstream::resolve(&url).await.unwrap();
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let lines = request_headers(&mut stream).await;
            assert_eq!(lines[0], "CONNECT example.test:443 HTTP/1.1\r\n");
            assert!(
                lines
                    .iter()
                    .any(|line| line == "Host: example.test:443\r\n")
            );
            let encoded = STANDARD.encode("up@stream:p:a ss");
            assert!(
                lines
                    .iter()
                    .any(|line| line == &format!("Proxy-Authorization: Basic {encoded}\r\n"))
            );
            stream
                .write_all(
                    b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\nContent-Length: 100\r\n\r\nhello",
                )
                .await
                .unwrap();
            let mut received = [0; 5];
            stream.read_exact(&mut received).await.unwrap();
            assert_eq!(&received, b"world");
        });
        let mut tunnel = upstream
            .connect(&"example.test:443".parse().unwrap())
            .await
            .unwrap();
        let mut received = [0; 5];
        timeout(TIMEOUT, tunnel.read_exact(&mut received))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&received, b"hello");
        tunnel.write_all(b"world").await.unwrap();
        timeout(TIMEOUT, proxy).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn rejects_malformed_and_oversized_response_heads() {
        let malformed = b"HTTP/1.1 200 OK\r\ninvalid-header\r\n\r\n".to_vec();
        let mut oversized = b"HTTP/1.1 200 OK\r\nX-Large: ".to_vec();
        oversized.extend(std::iter::repeat_n(b'x', MAX_RESPONSE_BYTES as usize));
        oversized.extend_from_slice(b"\r\n\r\n");
        for head in [malformed, oversized] {
            let mut stream = head.as_slice();
            assert!(read_connect_response(&mut stream).await.is_err());
        }
    }

    #[tokio::test]
    async fn upstream_407_rejects_tunnel_without_forwarding_challenge() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!("http://{}", listener.local_addr().unwrap())).unwrap();
        let upstream = Upstream::resolve(&url).await.unwrap();
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            request_headers(&mut stream).await;
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=private\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let error = upstream
            .connect(&"example.test:443".parse().unwrap())
            .await
            .err()
            .expect("407 must fail");
        assert_eq!(
            error.to_string(),
            "upstream proxy rejected CONNECT with status 407"
        );
        proxy.await.unwrap();
    }

    #[tokio::test]
    async fn https_proxy_sends_tls_before_any_credentials() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "https://user:secret@{}",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let upstream = Upstream::resolve(&url).await.unwrap();
        let proxy = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut prefix = [0; 3];
            stream.read_exact(&mut prefix).await.unwrap();
            assert_eq!(&prefix[..2], &[0x16, 0x03]);
            // Close during the TLS handshake. There must be no plaintext fallback.
        });
        let error = upstream
            .connect(&"example.test:443".parse().unwrap())
            .await
            .err()
            .expect("untrusted HTTPS proxy must fail");
        assert_eq!(
            error.to_string(),
            "TLS handshake with the upstream proxy failed"
        );
        proxy.await.unwrap();
    }

    #[test]
    fn rejects_delimiters_and_controls_in_credentials() {
        for url in [
            "http://user%3Aname:pass@127.0.0.1",
            "http://user:p%0Dass@127.0.0.1",
            "http://user:%FF@127.0.0.1",
        ] {
            assert!(authorization(&Url::parse(url).unwrap()).is_err(), "{url}");
        }
    }
}
