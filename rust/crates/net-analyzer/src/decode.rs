//! Link, network and transport layer decoding (Ethernet/VLAN, Linux cooked,
//! raw IP; IPv4 and IPv6; TCP and UDP). Anything else is ignored.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::pcap::{LINKTYPE_ETHERNET, LINKTYPE_LINUX_SLL, LINKTYPE_RAW};

pub const TCP_SYN: u8 = 0x02;
pub const TCP_ACK: u8 = 0x10;

/// Transport protocol of a decoded packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp { flags: u8 },
    Udp,
}

/// A decoded TCP or UDP packet borrowing its payload from the capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub transport: Transport,
    pub payload: &'a [u8],
}

fn be16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]))
}

fn strip_ethernet(data: &[u8]) -> Option<&[u8]> {
    let mut offset = 12;
    let mut ethertype = be16(data, offset)?;
    offset += 2;
    if ethertype == 0x8100 {
        ethertype = be16(data, offset + 2)?;
        offset += 4;
    }
    if ethertype == 0x0800 || ethertype == 0x86dd {
        data.get(offset..)
    } else {
        None
    }
}

fn strip_sll(data: &[u8]) -> Option<&[u8]> {
    let protocol = be16(data, 14)?;
    if protocol == 0x0800 || protocol == 0x86dd {
        data.get(16..)
    } else {
        None
    }
}

/// Decodes one captured packet. Returns `None` for unsupported or damaged packets.
pub fn decode(link_type: u32, data: &[u8]) -> Option<Decoded<'_>> {
    let ip = match link_type {
        LINKTYPE_ETHERNET => strip_ethernet(data)?,
        LINKTYPE_LINUX_SLL => strip_sll(data)?,
        LINKTYPE_RAW => data,
        _ => return None,
    };
    match ip.first()? >> 4 {
        4 => decode_v4(ip),
        6 => decode_v6(ip),
        _ => None,
    }
}

fn decode_v4(ip: &[u8]) -> Option<Decoded<'_>> {
    if ip.len() < 20 {
        return None;
    }
    let header_len = usize::from(ip[0] & 0x0f) * 4;
    if header_len < 20 || ip.len() < header_len {
        return None;
    }
    if be16(ip, 6)? & 0x1fff != 0 {
        return None;
    }
    let total = usize::from(be16(ip, 2)?);
    let end = if (header_len..=ip.len()).contains(&total) {
        total
    } else {
        ip.len()
    };
    let src = IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]));
    decode_l4(src, dst, ip[9], ip.get(header_len..end)?)
}

fn decode_v6(ip: &[u8]) -> Option<Decoded<'_>> {
    if ip.len() < 40 {
        return None;
    }
    let payload_len = usize::from(be16(ip, 4)?);
    let end = (40 + payload_len).min(ip.len());
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&ip[8..24]);
    dst.copy_from_slice(&ip[24..40]);
    let src = IpAddr::V6(Ipv6Addr::from(src));
    let dst = IpAddr::V6(Ipv6Addr::from(dst));
    decode_l4(src, dst, ip[6], ip.get(40..end)?)
}

fn decode_l4(src: IpAddr, dst: IpAddr, protocol: u8, l4: &[u8]) -> Option<Decoded<'_>> {
    match protocol {
        6 => {
            if l4.len() < 20 {
                return None;
            }
            let offset = usize::from(l4[12] >> 4) * 4;
            if offset < 20 {
                return None;
            }
            Some(Decoded {
                src,
                dst,
                src_port: be16(l4, 0)?,
                dst_port: be16(l4, 2)?,
                transport: Transport::Tcp { flags: l4[13] },
                payload: l4.get(offset..)?,
            })
        }
        17 => {
            if l4.len() < 8 {
                return None;
            }
            Some(Decoded {
                src,
                dst,
                src_port: be16(l4, 0)?,
                dst_port: be16(l4, 2)?,
                transport: Transport::Udp,
                payload: &l4[8..],
            })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{ethernet_frame, ipv4_packet, tcp_frame, udp_frame, udp_segment};

    const A: [u8; 4] = [10, 0, 0, 1];
    const B: [u8; 4] = [10, 0, 0, 2];

    #[test]
    fn decodes_ethernet_udp() {
        let frame = udp_frame(A, B, (40000, 53), b"hello");
        let d = decode(LINKTYPE_ETHERNET, &frame).unwrap();
        assert_eq!(d.src, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(d.dst, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!((d.src_port, d.dst_port), (40000, 53));
        assert_eq!(d.transport, Transport::Udp);
        assert_eq!(d.payload, b"hello");
    }

    #[test]
    fn decodes_tcp_flags() {
        let frame = tcp_frame(A, B, (5000, 443), TCP_SYN);
        let d = decode(LINKTYPE_ETHERNET, &frame).unwrap();
        assert_eq!(d.transport, Transport::Tcp { flags: TCP_SYN });
        assert_eq!(d.dst_port, 443);
        assert!(d.payload.is_empty());
    }

    #[test]
    fn decodes_vlan_tagged_frames() {
        let segment = udp_segment(1, 2, b"x");
        let ip = ipv4_packet(17, A, B, &segment);
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x81, 0x00, 0x00, 0x07, 0x08, 0x00]);
        frame.extend_from_slice(&ip);
        let d = decode(LINKTYPE_ETHERNET, &frame).unwrap();
        assert_eq!(d.payload, b"x");
    }

    #[test]
    fn decodes_raw_ip_and_linux_cooked() {
        let segment = udp_segment(1, 2, b"y");
        let ip = ipv4_packet(17, A, B, &segment);
        assert_eq!(decode(LINKTYPE_RAW, &ip).unwrap().payload, b"y");
        let mut cooked = vec![0u8; 14];
        cooked.extend_from_slice(&[0x08, 0x00]);
        cooked.extend_from_slice(&ip);
        assert_eq!(decode(LINKTYPE_LINUX_SLL, &cooked).unwrap().payload, b"y");
    }

    #[test]
    fn decodes_ipv6_udp() {
        let segment = udp_segment(1000, 53, b"hi");
        let mut ip = vec![0x60, 0, 0, 0];
        ip.extend_from_slice(&(segment.len() as u16).to_be_bytes());
        ip.push(17);
        ip.push(64);
        ip.extend_from_slice(&[0u8; 15]);
        ip.push(1);
        ip.extend_from_slice(&[0u8; 15]);
        ip.push(2);
        ip.extend_from_slice(&segment);
        let mut frame = vec![0u8; 12];
        frame.extend_from_slice(&[0x86, 0xdd]);
        frame.extend_from_slice(&ip);
        let d = decode(LINKTYPE_ETHERNET, &frame).unwrap();
        assert_eq!(d.src, "::1".parse::<IpAddr>().unwrap());
        assert_eq!(d.dst, "::2".parse::<IpAddr>().unwrap());
        assert_eq!(d.dst_port, 53);
        assert_eq!(d.payload, b"hi");
    }

    #[test]
    fn ignores_fragments_other_protocols_and_garbage() {
        let segment = udp_segment(1, 2, b"z");
        let mut ip = ipv4_packet(17, A, B, &segment);
        ip[7] = 8;
        assert!(decode(LINKTYPE_RAW, &ip).is_none());
        let icmp = ipv4_packet(1, A, B, &[8, 0, 0, 0]);
        assert!(decode(LINKTYPE_RAW, &icmp).is_none());
        assert!(decode(LINKTYPE_RAW, &[]).is_none());
        assert!(decode(LINKTYPE_RAW, &[0x45, 0, 0]).is_none());
        assert!(decode(LINKTYPE_ETHERNET, &[0u8; 5]).is_none());
        assert!(decode(999, &ip).is_none());
        let arp = ethernet_frame(&[0u8; 28]);
        assert!(decode(LINKTYPE_ETHERNET, &arp).is_none());
    }

    #[test]
    fn survives_truncated_transport_headers() {
        let ip = ipv4_packet(6, A, B, &[0u8; 10]);
        assert!(decode(LINKTYPE_RAW, &ip).is_none());
        let short_udp = ipv4_packet(17, A, B, &[0u8; 4]);
        assert!(decode(LINKTYPE_RAW, &short_udp).is_none());
    }
}
