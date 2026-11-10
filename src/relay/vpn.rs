//! TCP and DNS sockets scoped to one macOS point-to-point interface.
//!
//! Resolver API and bootstrap addresses are documented by Cloudflare.
//! https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/make-api-requests/dns-json/
//! https://developers.cloudflare.com/1.1.1.1/ip-addresses/
use std::{
    ffi::{CStr, CString},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    process::Command,
    time::Duration,
};

use anyhow::{Context, Result, anyhow, ensure};
use http::{Request, StatusCode, header, uri::Authority};
use http_body_util::{BodyExt, Empty};
use hyper::{body::Bytes, client::conn::http1};
use hyper_util::rt::TokioIo;
use serde::Deserialize;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    task::JoinSet,
    time::timeout,
};
use tokio_native_tls::TlsConnector;

use super::vpn_dns;

const DOH_HOST: &str = "cloudflare-dns.com";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DOH_BYTES: usize = 16 * 1024;

#[derive(PartialEq)]
struct Interface {
    index: NonZeroU32,
    addresses: Vec<IpAddr>,
}

struct Network {
    selected: Interface,
    local_addresses: Vec<IpAddr>,
}

struct InterfaceList(*mut libc::ifaddrs);

impl InterfaceList {
    fn read() -> Result<Self> {
        let mut list = std::ptr::null_mut();
        ensure!(
            unsafe { libc::getifaddrs(&mut list) } == 0,
            "could not read VPN interface state"
        );
        Ok(Self(list))
    }
}

impl Drop for InterfaceList {
    fn drop(&mut self) {
        unsafe { libc::freeifaddrs(self.0) };
    }
}

fn tunnel_flags(flags: u32) -> bool {
    let required = (libc::IFF_UP | libc::IFF_RUNNING | libc::IFF_POINTOPOINT) as u32;
    flags & required == required && flags & libc::IFF_LOOPBACK as u32 == 0
}

fn interface_address(entry: &libc::ifaddrs) -> Option<IpAddr> {
    if entry.ifa_addr.is_null() {
        return None;
    }
    unsafe {
        match i32::from((*entry.ifa_addr).sa_family) {
            libc::AF_INET => {
                let address = &*entry.ifa_addr.cast::<libc::sockaddr_in>();
                Some(IpAddr::V4(Ipv4Addr::from(
                    address.sin_addr.s_addr.to_ne_bytes(),
                )))
            }
            libc::AF_INET6 => {
                let address = &*entry.ifa_addr.cast::<libc::sockaddr_in6>();
                Some(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

pub(super) fn active_interfaces() -> Result<Vec<String>> {
    let list = InterfaceList::read()?;
    let mut entry = list.0;
    let mut names = Vec::new();
    while !entry.is_null() {
        let current = unsafe { &*entry };
        if tunnel_flags(current.ifa_flags)
            && interface_address(current).is_some_and(|address| allowed_destination(address, &[]))
            && !current.ifa_name.is_null()
            && let Ok(name) = unsafe { CStr::from_ptr(current.ifa_name) }.to_str()
            && valid_interface_name(name)
        {
            names.push(name.to_owned());
        }
        entry = current.ifa_next;
    }
    names.sort_unstable();
    names.dedup();
    Ok(names)
}

pub(super) fn candidates(requested: &str) -> Result<Vec<String>> {
    if requested != "auto" {
        return Ok(vec![requested.to_owned()]);
    }
    let active = active_interfaces()?;
    ensure!(
        !active.is_empty(),
        "no active VPN tunnel found; connect your VPN or configure its HTTP(S) proxy"
    );
    if active.len() == 1 {
        return Ok(active);
    }
    let mut routed = Vec::new();
    for route in [
        ["-inet", "default"],
        ["-inet6", "default"],
        ["-inet", "1.1.1.1"],
        ["-inet6", "2606:4700:4700::1111"],
    ] {
        if let Ok(output) = Command::new("/sbin/route")
            .args(["-n", "get"])
            .args(route)
            .env("LC_ALL", "C")
            .output()
            && output.status.success()
            && let Ok(name) = route_interface(&output.stdout)
            && active.contains(&name)
            && !routed.contains(&name)
        {
            routed.push(name);
        }
    }
    for name in active {
        if !routed.contains(&name) {
            routed.push(name);
        }
    }
    Ok(routed)
}

impl Network {
    fn read(name: &CStr) -> Result<Self> {
        let index = NonZeroU32::new(unsafe { libc::if_nametoindex(name.as_ptr()) })
            .context("VPN interface is unavailable")?;
        let list = InterfaceList::read()?;
        let mut entry = list.0;
        let mut flags = None;
        let mut addresses = Vec::new();
        let mut local_addresses = Vec::new();
        while !entry.is_null() {
            let current = unsafe { &*entry };
            let selected =
                !current.ifa_name.is_null() && unsafe { CStr::from_ptr(current.ifa_name) } == name;
            if selected {
                flags = Some(current.ifa_flags);
            }
            if let Some(address) = interface_address(current) {
                local_addresses.push(address);
                if selected && allowed_destination(address, &[]) {
                    addresses.push(address);
                }
            }
            entry = current.ifa_next;
        }
        let flags = flags.context("VPN interface disappeared")?;
        ensure!(
            tunnel_flags(flags),
            "VPN interface must be an active point-to-point tunnel"
        );
        addresses.sort_unstable();
        addresses.dedup();
        ensure!(
            !addresses.is_empty(),
            "VPN interface has no usable IP addresses"
        );
        ensure!(
            unsafe { libc::if_nametoindex(name.as_ptr()) } == index.get(),
            "VPN interface changed while reading its state"
        );
        Ok(Self {
            selected: Interface { index, addresses },
            local_addresses,
        })
    }
}

pub(super) struct Vpn {
    name: CString,
    interface: Interface,
    tls: TlsConnector,
    dns_config: Vec<u8>,
}

impl Vpn {
    pub(super) fn new(interface: &str) -> Result<Self> {
        ensure!(
            valid_interface_name(interface),
            "VPN interface name is invalid"
        );
        let name = CString::new(interface).context("VPN interface name contains a NUL byte")?;
        let network = Network::read(&name)?;
        let tls = native_tls::TlsConnector::new()
            .map_err(|_| anyhow!("could not initialize VPN DNS TLS"))?;
        let dns_config = Command::new("/usr/sbin/scutil")
            .arg("--dns")
            .env("LC_ALL", "C")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| output.stdout)
            .unwrap_or_default();
        Ok(Self {
            name,
            interface: network.selected,
            tls: TlsConnector::from(tls),
            dns_config,
        })
    }

    fn current_network(&self) -> Result<Network> {
        let network = Network::read(&self.name)?;
        ensure!(
            network.selected == self.interface,
            "VPN interface changed; restart the wrapper with the current tunnel"
        );
        Ok(network)
    }

    pub(super) async fn connect(
        &self,
        authority: &Authority,
    ) -> Result<impl AsyncRead + AsyncWrite + Unpin + Send + use<>> {
        ensure!(
            !authority.host().is_empty()
                && !authority.as_str().contains('@')
                && authority.port_u16().is_some_and(|port| port != 0),
            "VPN CONNECT requires a host and a nonzero port"
        );
        let host = authority.host();
        let host = host
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(host);
        let port = authority.port_u16().unwrap();
        timeout(CONNECT_TIMEOUT, async {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return self.dial(SocketAddr::new(ip, port)).await;
            }
            ensure!(
                valid_dns_name(host),
                "VPN CONNECT requires an ASCII DNS name"
            );
            let scoped = vpn_dns::scoped_servers(&self.dns_config, self.interface.index, host);
            let mut failure = None;
            for record_type in [1, 28] {
                if !self.supports_family(record_type == 1) {
                    continue;
                }
                let result = if scoped.is_empty() {
                    self.resolve(host, record_type).await
                } else {
                    self.resolve_scoped(&scoped, host, record_type).await
                };
                let addresses = match result {
                    Ok(addresses) => addresses,
                    Err(error) => {
                        failure = Some(error);
                        continue;
                    }
                };
                for address in addresses {
                    match timeout(ATTEMPT_TIMEOUT, self.dial(SocketAddr::new(address, port))).await
                    {
                        Ok(Ok(stream)) => return Ok(stream),
                        Ok(Err(error)) => failure = Some(error),
                        Err(_) => failure = Some(anyhow!("VPN-bound TCP connection timed out")),
                    }
                }
            }
            Err(failure.unwrap_or_else(|| anyhow!("VPN DNS did not return a usable address")))
                .context("could not reach the target through the pinned VPN interface")
        })
        .await
        .map_err(|_| anyhow!("VPN CONNECT timed out"))?
    }

    fn supports_family(&self, ipv4: bool) -> bool {
        self.interface
            .addresses
            .iter()
            .any(|address| address.is_ipv4() == ipv4)
    }

    fn bound_socket(&self, address: SocketAddr, kind: Type, protocol: Protocol) -> Result<Socket> {
        let network = self.current_network()?;
        ensure!(
            allowed_destination(address.ip(), &network.local_addresses),
            "VPN destination must be a remote unicast address"
        );
        let socket = Socket::new(Domain::for_address(address), kind, Some(protocol))?;
        socket.set_nonblocking(true)?;
        if address.is_ipv4() {
            socket.bind_device_by_index_v4(Some(self.interface.index))?;
            ensure!(
                socket.device_index_v4()? == Some(self.interface.index),
                "VPN IPv4 socket binding was not applied"
            );
        } else {
            socket.bind_device_by_index_v6(Some(self.interface.index))?;
            ensure!(
                socket.device_index_v6()? == Some(self.interface.index),
                "VPN IPv6 socket binding was not applied"
            );
        }
        Ok(socket)
    }

    fn verify_source(&self, source: IpAddr) -> Result<()> {
        self.current_network()?;
        ensure!(
            self.interface
                .addresses
                .iter()
                .any(|address| canonical_address(*address) == canonical_address(source)),
            "VPN-bound socket selected a source outside the pinned tunnel"
        );
        Ok(())
    }

    async fn dial(&self, address: SocketAddr) -> Result<TcpStream> {
        let socket = self.bound_socket(address, Type::STREAM, Protocol::TCP)?;
        if let Err(error) = socket.connect(&address.into()) {
            ensure!(
                error.raw_os_error() == Some(libc::EINPROGRESS),
                "could not initiate a VPN-bound TCP connection"
            );
        }
        let stream = TcpStream::from_std(socket.into())?;
        stream.writable().await?;
        if let Some(error) = stream.take_error()? {
            return Err(error).context("VPN-bound TCP connection failed");
        }
        stream
            .peer_addr()
            .context("VPN-bound TCP connection did not complete")?;
        self.verify_source(stream.local_addr()?.ip())?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    async fn resolve_scoped(
        &self,
        servers: &[IpAddr],
        host: &str,
        record_type: u16,
    ) -> Result<Vec<IpAddr>> {
        let (id, question) = vpn_dns::query(host, record_type)?;
        for server in servers
            .iter()
            .filter(|server| self.supports_family(server.is_ipv4()))
            .take(3)
        {
            let address = SocketAddr::new(*server, 53);
            if let Ok(Ok(response)) = timeout(
                Duration::from_millis(900),
                self.scoped_udp(address, &question),
            )
            .await
                && let Ok(addresses) = vpn_dns::response(&response, id, host, record_type)
            {
                return Ok(addresses);
            }
            // A truncated or unavailable UDP response can be retried over TCP
            // using the same scoped resolver, interface and validation.
            if let Ok(Ok(response)) = timeout(
                Duration::from_millis(1400),
                self.scoped_tcp(address, &question),
            )
            .await
                && let Ok(addresses) = vpn_dns::response(&response, id, host, record_type)
            {
                return Ok(addresses);
            }
        }
        Err(anyhow!(
            "the selected VPN's scoped DNS resolver did not return a valid response"
        ))
    }

    async fn scoped_udp(&self, address: SocketAddr, question: &[u8]) -> Result<Vec<u8>> {
        let socket = self.bound_socket(address, Type::DGRAM, Protocol::UDP)?;
        socket.connect(&address.into())?;
        let socket = UdpSocket::from_std(socket.into())?;
        self.verify_source(socket.local_addr()?.ip())?;
        ensure!(
            socket.send(question).await? == question.len(),
            "incomplete VPN DNS query"
        );
        let mut response = vec![0; MAX_DOH_BYTES + 1];
        let length = socket.recv(&mut response).await?;
        ensure!(length <= MAX_DOH_BYTES, "VPN DNS response is too large");
        self.verify_source(socket.local_addr()?.ip())?;
        response.truncate(length);
        Ok(response)
    }

    async fn scoped_tcp(&self, address: SocketAddr, question: &[u8]) -> Result<Vec<u8>> {
        let mut stream = self.dial(address).await?;
        stream.write_u16(u16::try_from(question.len())?).await?;
        stream.write_all(question).await?;
        let length = usize::from(stream.read_u16().await?);
        ensure!(length <= MAX_DOH_BYTES, "VPN DNS response is too large");
        let mut response = vec![0; length];
        stream.read_exact(&mut response).await?;
        self.verify_source(stream.local_addr()?.ip())?;
        Ok(response)
    }

    async fn resolve(&self, host: &str, record_type: u16) -> Result<Vec<IpAddr>> {
        let has_ipv4 = self.interface.addresses.iter().any(IpAddr::is_ipv4);
        let has_ipv6 = self.interface.addresses.iter().any(IpAddr::is_ipv6);
        let mut resolvers = Vec::new();
        if has_ipv4 {
            resolvers.extend([
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)),
            ]);
        }
        if has_ipv6 {
            resolvers.extend([
                "2606:4700:4700::1111".parse::<IpAddr>().unwrap(),
                "2606:4700:4700::1001".parse::<IpAddr>().unwrap(),
            ]);
        }
        for resolver in resolvers {
            if let Ok(Ok(body)) = timeout(
                ATTEMPT_TIMEOUT,
                self.doh(SocketAddr::new(resolver, 443), host, record_type),
            )
            .await
            {
                return dns_addresses(&body, host, record_type);
            }
        }
        Err(anyhow!("VPN DNS-over-HTTPS lookup failed"))
    }

    async fn doh(&self, resolver: SocketAddr, host: &str, record_type: u16) -> Result<Vec<u8>> {
        let stream = self.dial(resolver).await?;
        let stream = self
            .tls
            .connect(DOH_HOST, stream)
            .await
            .map_err(|_| anyhow!("VPN DNS TLS verification failed"))?;
        let body = exchange_dns(stream, host, record_type).await?;
        self.current_network()?;
        Ok(body)
    }
}

async fn exchange_dns(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    host: &str,
    record_type: u16,
) -> Result<Vec<u8>> {
    let (mut sender, connection) = http1::handshake(TokioIo::new(stream)).await?;
    let mut target = reqwest::Url::parse("https://cloudflare-dns.com/dns-query")?;
    target
        .query_pairs_mut()
        .append_pair("name", host)
        .append_pair("type", &record_type.to_string());
    let request = Request::builder()
        .uri(format!("/dns-query?{}", target.query().unwrap()))
        .header(header::HOST, DOH_HOST)
        .header(header::ACCEPT, "application/dns-json")
        .header(header::CONNECTION, "close")
        .body(Empty::<Bytes>::new())?;
    let exchange = async move {
        let response = sender.send_request(request).await?;
        ensure!(
            response.status() == StatusCode::OK,
            "VPN DNS service rejected the query"
        );
        let mut incoming = response.into_body();
        let mut body = Vec::new();
        while let Some(frame) = incoming.frame().await {
            if let Ok(data) = frame?.into_data() {
                ensure!(
                    data.len() <= MAX_DOH_BYTES - body.len(),
                    "VPN DNS response is too large"
                );
                body.extend_from_slice(&data);
            }
        }
        Ok::<_, anyhow::Error>(body)
    };
    // A complete HTTP body is sufficient. Some resolvers close TLS without a
    // close_notify after it, so keep the driver only for the framed exchange.
    let mut driver = JoinSet::new();
    driver.spawn(connection);
    let body = exchange.await?;
    drop(driver);
    Ok(body)
}

fn valid_dns_name(name: &str) -> bool {
    let name = name.strip_suffix('.').unwrap_or(name);
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

fn route_interface(output: &[u8]) -> Result<String> {
    let output = std::str::from_utf8(output).context("VPN bootstrap route output was not UTF-8")?;
    let mut interfaces = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("interface:"));
    let interface = interfaces
        .next()
        .context("VPN bootstrap route has no interface")?
        .trim();
    ensure!(
        interfaces.next().is_none() && valid_interface_name(interface),
        "VPN bootstrap route interface is invalid or ambiguous"
    );
    Ok(interface.to_owned())
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < libc::IFNAMSIZ
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn canonical_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

fn allowed_destination(address: IpAddr, local_addresses: &[IpAddr]) -> bool {
    let address = canonical_address(address);
    !address.is_loopback()
        && !address.is_unspecified()
        && !address.is_multicast()
        && !match address {
            IpAddr::V4(ip) => ip.octets()[0] == 0 || ip.is_link_local() || ip.is_broadcast(),
            IpAddr::V6(ip) => ip.is_unicast_link_local(),
        }
        && !local_addresses
            .iter()
            .any(|local| canonical_address(*local) == address)
}

#[derive(Deserialize)]
struct DnsResponse {
    #[serde(rename = "Status")]
    status: u16,
    #[serde(rename = "TC")]
    truncated: bool,
    #[serde(rename = "Question")]
    questions: Vec<DnsQuestion>,
    #[serde(default, rename = "Answer")]
    answers: Vec<DnsAnswer>,
}

#[derive(Deserialize)]
struct DnsQuestion {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
}

#[derive(Deserialize)]
struct DnsAnswer {
    name: String,
    #[serde(rename = "type")]
    record_type: u16,
    data: String,
}

fn dns_addresses(body: &[u8], host: &str, record_type: u16) -> Result<Vec<IpAddr>> {
    let response: DnsResponse =
        serde_json::from_slice(body).map_err(|_| anyhow!("VPN DNS response was malformed"))?;
    ensure!(
        response.status == 0
            && !response.truncated
            && response.questions.len() == 1
            && response.questions[0].record_type == record_type
            && response.questions[0]
                .name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(host.trim_end_matches('.')),
        "VPN DNS response did not match the query"
    );
    let mut addresses = Vec::new();
    let mut names = vec![host.trim_end_matches('.').to_ascii_lowercase()];
    for _ in 0..16 {
        let current = names.last().unwrap();
        let mut aliases = response.answers.iter().filter(|answer| {
            answer.record_type == 5
                && answer
                    .name
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(current)
        });
        let Some(alias) = aliases.next() else { break };
        let target = alias.data.trim_end_matches('.').to_ascii_lowercase();
        ensure!(
            aliases.next().is_none() && valid_dns_name(&target) && !names.contains(&target),
            "VPN DNS returned an invalid or cyclic CNAME chain"
        );
        names.push(target);
    }
    ensure!(names.len() <= 16, "VPN DNS CNAME chain is too long");
    let terminal_name = names.last().unwrap();
    for answer in response.answers {
        if answer.record_type == record_type
            && answer
                .name
                .trim_end_matches('.')
                .eq_ignore_ascii_case(terminal_name)
        {
            let address: IpAddr = answer
                .data
                .parse()
                .map_err(|_| anyhow!("VPN DNS returned an invalid IP address"))?;
            ensure!(
                (record_type == 1 && address.is_ipv4()) || (record_type == 28 && address.is_ipv6()),
                "VPN DNS returned an address of the wrong family"
            );
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    #[test]
    fn rejects_missing_and_non_tunnel_interfaces() {
        for name in ["", "lo0", "cw-invalid-vpn", "a\0b"] {
            assert!(Vpn::new(name).is_err(), "{name:?}");
        }
    }

    #[test]
    fn blocks_local_special_and_assigned_addresses() {
        let assigned = [
            "192.0.2.5".parse().unwrap(),
            "fd00::5".parse().unwrap(),
            "::ffff:192.0.2.6".parse().unwrap(),
        ];
        for value in [
            "127.0.0.1",
            "::1",
            "0.0.0.0",
            "::",
            "169.254.1.1",
            "fe80::1",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "::ffff:127.0.0.1",
            "192.0.2.5",
            "fd00::5",
            "192.0.2.6",
            "0.1.2.3",
        ] {
            assert!(
                !allowed_destination(value.parse().unwrap(), &assigned),
                "{value}"
            );
        }
        assert!(allowed_destination(
            "10.23.45.6".parse().unwrap(),
            &assigned
        ));
        assert!(allowed_destination("1.1.1.1".parse().unwrap(), &assigned));
    }

    #[test]
    fn validates_doh_question_and_address_family() {
        let valid = br#"{"Status":0,"TC":false,"Question":[{"name":"example.com.","type":1}],"Answer":[{"name":"example.com.","type":1,"data":"192.0.2.1"}]}"#;
        assert_eq!(
            dns_addresses(valid, "example.com", 1).unwrap(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        assert!(dns_addresses(valid, "other.test", 1).is_err());
        assert!(dns_addresses(valid, "example.com", 28).is_err());
        assert!(!valid_dns_name("example.com/path"));
        assert!(!valid_dns_name("invalid..test"));
        assert!(valid_dns_name("xn--bcher-kva.example"));
    }

    #[test]
    fn follows_only_matching_cname_owners() {
        let response = br#"{"Status":0,"TC":false,"Question":[{"name":"example.com.","type":1}],"Answer":[{"name":"example.com.","type":5,"data":"edge.example.net."},{"name":"unrelated.test.","type":1,"data":"192.0.2.9"},{"name":"edge.example.net.","type":1,"data":"192.0.2.1"}]}"#;
        assert_eq!(
            dns_addresses(response, "example.com", 1).unwrap(),
            ["192.0.2.1".parse::<IpAddr>().unwrap()]
        );
        let cycle = br#"{"Status":0,"TC":false,"Question":[{"name":"example.com.","type":1}],"Answer":[{"name":"example.com.","type":5,"data":"example.com."}]}"#;
        assert!(dns_addresses(cycle, "example.com", 1).is_err());
    }

    #[test]
    fn parses_bootstrap_route_without_retargeting_a_session() {
        assert_eq!(
            route_interface(b"route to: default\n interface: utun4\n").unwrap(),
            "utun4"
        );
        assert!(route_interface(b"interface: utun4\ninterface: en0\n").is_err());
        assert!(route_interface(b"interface: \n").is_err());
        assert!(route_interface(b"gateway: 192.0.2.1\n").is_err());
    }

    #[tokio::test]
    async fn dns_body_completion_does_not_wait_for_remote_connection_close() {
        let (client, server) = tokio::io::duplex(4096);
        let serve = async move {
            let mut server = BufReader::new(server);
            loop {
                let mut line = String::new();
                assert_ne!(server.read_line(&mut line).await.unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
            }
            server
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await
                .unwrap();
            std::future::pending::<()>().await;
        };
        tokio::select! {
            _ = serve => unreachable!(),
            body = timeout(Duration::from_secs(1), exchange_dns(client, "example.com", 1)) => {
                assert_eq!(body.unwrap().unwrap(), b"{}");
            }
        }
    }

    #[tokio::test]
    #[ignore = "requires an operator-selected active VPN interface"]
    async fn live_vpn_dns_and_tls() {
        let interface = std::env::var("CLAUDE_WRAPPER_TEST_VPN").expect("select the VPN interface");
        let selected = candidates(&interface).unwrap();
        let vpn = Vpn::new(&selected[0]).unwrap();
        let target = std::env::var("CLAUDE_WRAPPER_TEST_VPN_TARGET")
            .unwrap_or_else(|_| "api.country.is:443".into())
            .parse::<Authority>()
            .unwrap();
        let stream = vpn.connect(&target).await.unwrap();
        let tls = native_tls::TlsConnector::new().unwrap();
        TlsConnector::from(tls)
            .connect(target.host(), stream)
            .await
            .unwrap();
    }
}
