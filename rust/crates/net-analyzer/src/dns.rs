//! DNS question parsing (first question only) and a small entropy helper.

/// The first question of a DNS message plus the response code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    /// Lowercase query name without the trailing dot.
    pub name: String,
    pub qtype: u16,
    pub is_response: bool,
    pub rcode: u8,
}

/// Reads a (possibly compressed) name. Returns the name and the offset right
/// after it in the original position.
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end: Option<usize> = None;
    let mut jumps = 0;
    loop {
        let len = *msg.get(pos)?;
        if len == 0 {
            let after = end.unwrap_or(pos + 1);
            return Some((labels.join("."), after));
        }
        if (len & 0xc0) == 0xc0 {
            let low = *msg.get(pos + 1)?;
            if end.is_none() {
                end = Some(pos + 2);
            }
            jumps += 1;
            if jumps > 8 {
                return None;
            }
            pos = (usize::from(len & 0x3f) << 8) | usize::from(low);
            continue;
        }
        if len > 63 {
            return None;
        }
        let size = usize::from(len);
        let label = msg.get(pos + 1..pos + 1 + size)?;
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        if labels.len() > 127 {
            return None;
        }
        pos += 1 + size;
    }
}

/// Parses the header and the first question of a DNS message.
pub fn parse(payload: &[u8]) -> Option<DnsMessage> {
    if payload.len() < 12 {
        return None;
    }
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    let questions = u16::from_be_bytes([payload[4], payload[5]]);
    if questions == 0 {
        return None;
    }
    let (name, next) = read_name(payload, 12)?;
    let qtype = u16::from_be_bytes([*payload.get(next)?, *payload.get(next + 1)?]);
    Some(DnsMessage {
        name,
        qtype,
        is_response: flags & 0x8000 != 0,
        rcode: (flags & 0x000f) as u8,
    })
}

/// Shannon entropy in bits per byte.
pub fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in text.bytes() {
        counts[usize::from(byte)] += 1;
    }
    let len = text.len() as f64;
    let mut total = 0.0;
    for &count in counts.iter().filter(|&&c| c > 0) {
        let p = count as f64 / len;
        total -= p * p.log2();
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::dns_message;

    #[test]
    fn parses_queries_and_responses() {
        let query = parse(&dns_message("WWW.Example.COM", 1, false, 0)).unwrap();
        assert_eq!(query.name, "www.example.com");
        assert_eq!(query.qtype, 1);
        assert!(!query.is_response);
        let answer = parse(&dns_message("nope.example.com", 28, true, 3)).unwrap();
        assert!(answer.is_response);
        assert_eq!(answer.rcode, 3);
        assert_eq!(answer.qtype, 28);
    }

    #[test]
    fn follows_compression_pointers() {
        let mut msg = vec![0u8; 12];
        msg[5] = 1;
        msg.extend_from_slice(&[1, b'a', 0xc0, 20]);
        msg.extend_from_slice(&[0, 1, 0, 1]);
        msg.extend_from_slice(b"\x07example\x03com\x00");
        let parsed = parse(&msg).unwrap();
        assert_eq!(parsed.name, "a.example.com");
        assert_eq!(parsed.qtype, 1);
    }

    #[test]
    fn rejects_pointer_loops_and_garbage() {
        let mut msg = vec![0u8; 12];
        msg[5] = 1;
        msg.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]);
        assert!(parse(&msg).is_none());
        assert!(parse(&[0u8; 5]).is_none());
        assert!(parse(&[0u8; 12]).is_none());
        let mut long_label = vec![0u8; 12];
        long_label[5] = 1;
        long_label.push(64);
        long_label.extend_from_slice(&[b'a'; 64]);
        assert!(parse(&long_label).is_none());
    }

    #[test]
    fn entropy_separates_random_from_plain_text() {
        assert_eq!(shannon_entropy(""), 0.0);
        assert_eq!(shannon_entropy("aaaaaaaa"), 0.0);
        assert!(shannon_entropy("x8k2jf9sl2kd93jf7q") > 3.5);
        assert!(shannon_entropy("google") < 3.0);
    }
}
