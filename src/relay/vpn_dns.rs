//! Resolver selection and DNS messages for the interface-bound VPN transport.
//! Wire format: https://www.rfc-editor.org/rfc/rfc1035.html#section-4

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
};

use anyhow::{Context, Result, anyhow, ensure};

const A: u16 = 1;
const AAAA: u16 = 28;
const CNAME: u16 = 5;
const IN: u16 = 1;
const HEADER_LEN: usize = 12;
const MAX_RECORDS: usize = 256;

#[derive(Default)]
struct Resolver {
    index: Option<u32>,
    domain: Option<String>,
    order: Option<u32>,
    servers: BTreeMap<u16, Option<IpAddr>>,
    invalid: bool,
}

impl Resolver {
    fn read(&mut self, key: &str, value: &str) {
        match key {
            "if_index" => {
                let index = interface_index(value);
                self.invalid |= index.is_none() || self.index.is_some();
                self.index = index;
            }
            "domain" => {
                let domain = value.trim_end_matches('.').to_ascii_lowercase();
                self.invalid |=
                    self.domain.is_some() || (!domain.is_empty() && hostname(&domain).is_none());
                self.domain = Some(domain);
            }
            "order" => {
                let order = value.parse().ok();
                self.invalid |= order.is_none() || self.order.is_some();
                self.order = order;
            }
            // This transport uses standard unicast DNS on port 53.
            "port" if value != "53" => self.invalid = true,
            "options" if value.split_ascii_whitespace().any(|part| part == "mdns") => {
                self.invalid = true;
            }
            _ => {
                if let Some(slot) = key
                    .strip_prefix("nameserver[")
                    .and_then(|key| key.strip_suffix(']'))
                    .and_then(|slot| slot.parse::<u16>().ok())
                {
                    let address = value.parse().ok().and_then(unicast_resolver);
                    self.invalid |= self.servers.insert(slot, address).is_some();
                }
            }
        }
    }

    fn specificity(&self, index: NonZeroU32, host: &str) -> Option<usize> {
        if self.invalid || self.index != Some(index.get()) {
            return None;
        }
        let domain = self.domain.as_deref().unwrap_or("");
        (domain.is_empty()
            || host == domain
            || host
                .strip_suffix(domain)
                .is_some_and(|prefix| prefix.ends_with('.')))
        .then_some(domain.len())
    }
}

fn interface_index(value: &str) -> Option<u32> {
    let mut fields = value.split_ascii_whitespace();
    let index = fields.next()?.parse::<NonZeroU32>().ok()?;
    if let Some(name) = fields.next() {
        let name = name.strip_prefix('(')?.strip_suffix(')')?;
        if name.is_empty()
            || name.len() >= libc::IFNAMSIZ
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
            || fields.next().is_some()
        {
            return None;
        }
    }
    Some(index.get())
}

fn unicast_resolver(address: IpAddr) -> Option<IpAddr> {
    let address = match address {
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(address),
        _ => address,
    };
    let eligible = !address.is_unspecified()
        && !address.is_loopback()
        && !address.is_multicast()
        && match address {
            IpAddr::V4(ip) => ip.octets()[0] != 0 && !ip.is_link_local() && !ip.is_broadcast(),
            IpAddr::V6(ip) => !ip.is_unicast_link_local(),
        };
    eligible.then_some(address)
}

pub(super) fn scoped_servers(output: &[u8], index: NonZeroU32, host: &str) -> Vec<IpAddr> {
    let (Ok(output), Some(host)) = (std::str::from_utf8(output), hostname(host)) else {
        return Vec::new();
    };
    let host = host.to_ascii_lowercase();
    let mut resolvers: Vec<Resolver> = Vec::new();
    let mut current: Option<Resolver> = None;
    for line in output.lines().map(str::trim) {
        if line.starts_with("resolver #") || line.starts_with("DNS configuration") {
            if let Some(resolver) = current.take() {
                resolvers.push(resolver);
            }
            if line
                .strip_prefix("resolver #")
                .is_some_and(|number| number.parse::<u32>().is_ok())
            {
                current = Some(Resolver::default());
            }
        } else if let (Some(resolver), Some((key, value))) = (&mut current, line.split_once(':')) {
            resolver.read(key.trim(), value.trim());
        }
    }
    resolvers.extend(current);

    let mut matching = resolvers
        .into_iter()
        .filter_map(|resolver| Some((resolver.specificity(index, &host)?, resolver)))
        .collect::<Vec<_>>();
    matching.sort_by_key(|(specificity, resolver)| {
        (
            std::cmp::Reverse(*specificity),
            resolver.order.unwrap_or(u32::MAX),
        )
    });
    let Some((best, _)) = matching.first() else {
        return Vec::new();
    };
    let best = *best;
    let mut servers = Vec::new();
    for (_, resolver) in matching
        .into_iter()
        .take_while(|(specificity, _)| *specificity == best)
    {
        for server in resolver.servers.into_values().flatten() {
            if !servers.contains(&server) {
                servers.push(server);
            }
        }
    }
    servers
}

fn valid_label(label: &[u8]) -> bool {
    label.len() <= 63
        && label.first().is_some_and(u8::is_ascii_alphanumeric)
        && label.last().is_some_and(u8::is_ascii_alphanumeric)
        && label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'-')
}

fn hostname(host: &str) -> Option<&str> {
    let host = host.strip_suffix('.').unwrap_or(host);
    (host.len() <= 253 && host.split('.').all(|label| valid_label(label.as_bytes())))
        .then_some(host)
}

fn question_name(host: &str, record_type: u16) -> Result<Vec<u8>> {
    ensure!(
        matches!(record_type, A | AAAA),
        "unsupported VPN DNS query type"
    );
    let host = hostname(host).context("invalid VPN DNS query name")?;
    let mut name = Vec::with_capacity(host.len() + 2);
    for label in host.split('.') {
        name.push(label.len() as u8);
        name.extend(label.bytes().map(|byte| byte.to_ascii_lowercase()));
    }
    name.push(0);
    Ok(name)
}

pub(super) fn query(host: &str, record_type: u16) -> Result<(u16, Vec<u8>)> {
    let name = question_name(host, record_type)?;
    let mut id = [0; 2];
    getrandom::fill(&mut id).map_err(|_| anyhow!("could not generate VPN DNS transaction ID"))?;
    let mut packet = Vec::with_capacity(HEADER_LEN + name.len() + 4);
    packet.extend_from_slice(&id);
    // Recursive query with one question and no resource records.
    packet.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    packet.extend_from_slice(&name);
    packet.extend_from_slice(&record_type.to_be_bytes());
    packet.extend_from_slice(&IN.to_be_bytes());
    Ok((u16::from_be_bytes(id), packet))
}

fn take<'a>(packet: &'a [u8], cursor: &mut usize, length: usize) -> Result<&'a [u8]> {
    let end = *cursor + length;
    let bytes = packet
        .get(*cursor..end)
        .context("incomplete VPN DNS message")?;
    *cursor = end;
    Ok(bytes)
}

fn number(packet: &[u8], cursor: &mut usize) -> Result<u16> {
    let bytes = take(packet, cursor, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn name(packet: &[u8], cursor: &mut usize) -> Result<Vec<u8>> {
    let mut expanded = Vec::new();
    let mut position = *cursor;
    let mut limit = packet.len();
    let mut jumps = 0;
    loop {
        let start = position;
        let octet = take(&packet[..limit], &mut position, 1)?[0];
        if octet & 0xc0 == 0xc0 {
            let low = take(&packet[..limit], &mut position, 1)?[0];
            let offset = usize::from(u16::from_be_bytes([octet & 0x3f, low]));
            ensure!(
                offset >= HEADER_LEN && offset < start && jumps < 32,
                "invalid VPN DNS compression pointer"
            );
            if jumps == 0 {
                *cursor = position;
            }
            jumps += 1;
            // The name at the pointer target must end before this pointer.
            // Repeated pointers always shrink this range.
            limit = start;
            position = offset;
            continue;
        }
        ensure!(octet <= 63, "invalid VPN DNS label encoding");
        ensure!(
            expanded.len() + usize::from(octet) < 255,
            "VPN DNS name is too long"
        );
        expanded.push(octet);
        if octet == 0 {
            if jumps == 0 {
                *cursor = position;
            }
            return Ok(expanded);
        }
        let label = take(&packet[..limit], &mut position, usize::from(octet))?;
        expanded.extend(label.iter().map(|byte| byte.to_ascii_lowercase()));
    }
}

enum Answer {
    Alias(Vec<u8>),
    Address(IpAddr),
}

fn alias_is_hostname(mut alias: &[u8]) -> bool {
    if alias == [0] {
        return false;
    }
    loop {
        let Some((&length, remaining)) = alias.split_first() else {
            return false;
        };
        if length == 0 {
            return remaining.is_empty();
        }
        let length = usize::from(length);
        if remaining.len() < length || !valid_label(&remaining[..length]) {
            return false;
        }
        alias = &remaining[length..];
    }
}

pub(super) fn response(body: &[u8], id: u16, host: &str, record_type: u16) -> Result<Vec<IpAddr>> {
    ensure!(
        (HEADER_LEN..=65535).contains(&body.len()),
        "invalid VPN DNS response length"
    );
    let mut cursor = 0;
    ensure!(
        number(body, &mut cursor)? == id,
        "VPN DNS transaction ID did not match"
    );
    let flags = number(body, &mut cursor)?;
    ensure!(
        flags & 0xf800 == 0x8000 && flags & 0x0240 == 0,
        "invalid or truncated VPN DNS response"
    );
    let rcode = flags & 0x000f;
    ensure!(
        matches!(rcode, 0 | 3),
        "VPN DNS resolver rejected the query"
    );
    ensure!(
        number(body, &mut cursor)? == 1,
        "VPN DNS response must contain one question"
    );
    let answers = usize::from(number(body, &mut cursor)?);
    let authority = usize::from(number(body, &mut cursor)?);
    let additional = usize::from(number(body, &mut cursor)?);
    let total = answers + authority + additional;
    ensure!(
        total <= MAX_RECORDS,
        "VPN DNS response has too many records"
    );
    let expected = question_name(host, record_type)?;
    ensure!(
        name(body, &mut cursor)? == expected
            && number(body, &mut cursor)? == record_type
            && number(body, &mut cursor)? == IN,
        "VPN DNS response did not match the question"
    );
    let mut records = Vec::new();
    for index in 0..total {
        let owner = name(body, &mut cursor)?;
        let kind = number(body, &mut cursor)?;
        let class = number(body, &mut cursor)?;
        take(body, &mut cursor, 4)?; // TTL
        let length = usize::from(number(body, &mut cursor)?);
        let start = cursor;
        let data = take(body, &mut cursor, length)?;
        if class != IN || index >= answers {
            continue;
        }
        let answer = match kind {
            CNAME => {
                let mut alias_start = start;
                let alias = name(&body[..cursor], &mut alias_start)?;
                ensure!(
                    alias_start == cursor && alias_is_hostname(&alias),
                    "invalid VPN DNS CNAME"
                );
                Answer::Alias(alias)
            }
            A if record_type == A => {
                let bytes: [u8; 4] = data
                    .try_into()
                    .context("invalid VPN DNS IPv4 address length")?;
                Answer::Address(Ipv4Addr::from(bytes).into())
            }
            AAAA if record_type == AAAA => {
                let bytes: [u8; 16] = data
                    .try_into()
                    .context("invalid VPN DNS IPv6 address length")?;
                Answer::Address(Ipv6Addr::from(bytes).into())
            }
            _ => continue,
        };
        records.push((owner, answer));
    }
    ensure!(cursor == body.len(), "trailing data in VPN DNS response");
    if rcode == 3 {
        return Ok(Vec::new());
    }

    let mut chain = vec![expected.as_slice()];
    loop {
        let current = *chain.last().unwrap();
        let mut aliases = records.iter().filter_map(|(owner, answer)| match answer {
            Answer::Alias(alias) if owner == current => Some(alias.as_slice()),
            _ => None,
        });
        let Some(alias) = aliases.next() else { break };
        ensure!(
            !aliases.any(|other| other != alias) && !chain.contains(&alias) && chain.len() < 16,
            "invalid or cyclic VPN DNS CNAME chain"
        );
        chain.push(alias);
    }
    let terminal = *chain.last().unwrap();
    let mut addresses = Vec::new();
    for (owner, answer) in records.iter() {
        if let Answer::Address(address) = answer {
            ensure!(
                owner == terminal || !chain.contains(&owner.as_slice()),
                "conflicting VPN DNS alias and address"
            );
            if owner == terminal && !addresses.contains(address) {
                addresses.push(*address);
            }
        }
    }
    Ok(addresses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_dns_within_the_exact_interface_and_most_specific_domain() {
        let configuration = b"DNS configuration\n\
            resolver #1\n domain : example.com\n nameserver[0] : 192.0.2.1\n\
            resolver #2\n domain : example.com\n nameserver[0] : 192.0.2.2\n if_index : 180 (utun8)\n\
            resolver #3\n domain : example.com\n nameserver[0] : 192.0.2.3\n if_index : 18 (utun6)\n\
            resolver #4\n domain : sub.example.com\n nameserver[0] : 198.18.0.2\n if_index : 18 (utun6)\n order : 90\n\
            resolver #5\n domain : SUB.EXAMPLE.COM.\n nameserver[0] : 198.18.0.1\n if_index : 18 (utun6)\n order : 80\n\
            DNS configuration (for scoped queries)\n\
            resolver #1\n nameserver[0] : 192.0.2.5\n nameserver[1] : 127.0.0.1\n if_index : 18 (utun6)\n\
            resolver #2\n nameserver[0] : 192.0.2.6\n if_index : 18 (utun6)\n if_index : 20 (utun7)\n";
        let index = NonZeroU32::new(18).unwrap();
        let servers = |host| scoped_servers(configuration, index, host);
        let ip = |value: &str| value.parse::<IpAddr>().unwrap();
        assert_eq!(
            servers("api.sub.example.com"),
            [ip("198.18.0.1"), ip("198.18.0.2")]
        );
        assert_eq!(servers("example.com"), [ip("192.0.2.3")]);
        assert_eq!(servers("notexample.com"), [ip("192.0.2.5")]);
    }

    fn rr(packet: &mut Vec<u8>, owner: &[u8], kind: u16, data: &[u8]) {
        packet.extend_from_slice(owner);
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&IN.to_be_bytes());
        packet.extend_from_slice(&60u32.to_be_bytes());
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);
    }

    #[test]
    fn accepts_only_addresses_from_the_queried_alias_chain() {
        let (id, mut packet) = query("Example.com.", A).unwrap();
        packet[2..4].copy_from_slice(&[0x81, 0x80]);
        packet[7] = 3;
        packet[11] = 1;
        // Compressed CNAME and two unrelated addresses, including additional glue.
        rr(&mut packet, &[0xc0, 12], CNAME, b"\x04edge\xc0\x0c");
        rr(&mut packet, b"\x05other\xc0\x0c", A, &[192, 0, 2, 99]);
        rr(&mut packet, b"\x04edge\xc0\x0c", A, &[198, 18, 0, 4]);
        rr(&mut packet, b"\x04edge\xc0\x0c", A, &[192, 0, 2, 100]);
        assert_eq!(
            response(&packet, id, "example.com", A).unwrap(),
            [IpAddr::V4(Ipv4Addr::new(198, 18, 0, 4))]
        );
        assert!(response(&packet, id.wrapping_add(1), "example.com", A).is_err());
        assert!(response(&packet, id, "other.com", A).is_err());
        assert!(response(&packet, id, "example.com", AAAA).is_err());
        assert!(response(&packet[..packet.len() - 1], id, "example.com", A).is_err());
    }

    #[test]
    fn rejects_cyclic_aliases_and_invalid_or_truncated_messages() {
        let (id, mut packet) = query("example.com", AAAA).unwrap();
        packet[2..4].copy_from_slice(&[0x81, 0x80]);
        packet[7] = 1;
        let position = packet.len();
        rr(&mut packet, &[0xc0, 12], CNAME, &[0xc0, 12]);
        assert!(response(&packet, id, "example.com", AAAA).is_err());
        packet[position + 1] = position as u8;
        assert!(response(&packet, id, "example.com", AAAA).is_err());
        packet[2] |= 0x02;
        assert!(response(&packet, id, "example.com", AAAA).is_err());
        assert!(query("example.com/path", A).is_err());
    }
}
