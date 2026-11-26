//! Minimal IP network (address with prefix length) used for the IOC address list.

use std::net::IpAddr;

/// An address or a CIDR range such as `203.0.113.0/24`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

impl IpNet {
    /// Parses `1.2.3.4`, `1.2.3.0/24` or an IPv6 equivalent.
    pub fn parse(text: &str) -> Option<Self> {
        let (addr_text, prefix_text) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr_text.trim().parse().ok()?;
        let max: u8 = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_text {
            Some(p) => p.trim().parse::<u8>().ok()?,
            None => max,
        };
        if prefix > max {
            return None;
        }
        Some(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(candidate)) => {
                let mask = mask_v4(self.prefix);
                (u32::from(net) & mask) == (u32::from(candidate) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(candidate)) => {
                let mask = mask_v6(self.prefix);
                (u128::from(net) & mask) == (u128::from(candidate) & mask)
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn exact_addresses_match_only_themselves() {
        let net = IpNet::parse("203.0.113.5").unwrap();
        assert!(net.contains(ip("203.0.113.5")));
        assert!(!net.contains(ip("203.0.113.6")));
    }

    #[test]
    fn cidr_ranges_match_their_members() {
        let net = IpNet::parse("203.0.113.0/24").unwrap();
        assert!(net.contains(ip("203.0.113.77")));
        assert!(!net.contains(ip("203.0.114.1")));
        let everything = IpNet::parse("0.0.0.0/0").unwrap();
        assert!(everything.contains(ip("8.8.8.8")));
    }

    #[test]
    fn ipv6_ranges_work_and_families_do_not_mix() {
        let net = IpNet::parse("2001:db8::/32").unwrap();
        assert!(net.contains(ip("2001:db8:1::1")));
        assert!(!net.contains(ip("2001:db9::1")));
        assert!(!net.contains(ip("10.0.0.1")));
    }

    #[test]
    fn rejects_invalid_entries() {
        assert!(IpNet::parse("1.2.3.4/33").is_none());
        assert!(IpNet::parse("::1/129").is_none());
        assert!(IpNet::parse("not-an-ip").is_none());
        assert!(IpNet::parse("1.2.3.4/x").is_none());
        assert!(IpNet::parse("").is_none());
    }
}
