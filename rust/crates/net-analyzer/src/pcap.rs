//! Minimal reader for the classic libpcap capture format (not pcapng).

use std::io::{self, Read};

use thiserror::Error;

pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW: u32 = 101;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
const GLOBAL_HEADER_LEN: usize = 24;
const RECORD_HEADER_LEN: usize = 16;
const MAX_PACKET_LEN: u32 = 262_144;

/// Errors while reading a capture.
#[derive(Debug, Error)]
pub enum PcapError {
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("not a classic pcap capture (bad magic number)")]
    BadMagic,
    #[error("packet record of {0} bytes exceeds the limit")]
    PacketTooLarge(u32),
    #[error("truncated pcap data")]
    Truncated,
}

/// One captured packet.
#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    /// Capture time in seconds since the epoch.
    pub timestamp: f64,
    pub data: Vec<u8>,
}

/// Streaming reader over any byte source.
pub struct PcapReader<R> {
    reader: R,
    big_endian: bool,
    nanos: bool,
    link_type: u32,
}

fn read_u32(bytes: &[u8], big_endian: bool) -> u32 {
    let raw = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if big_endian {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    }
}

/// Fills `buf`. Returns `Ok(false)` on a clean end of input before the first
/// byte and `Truncated` if the input ends in the middle of the buffer.
fn read_full<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<bool, PcapError> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..])?;
        if n == 0 {
            if filled == 0 {
                return Ok(false);
            }
            return Err(PcapError::Truncated);
        }
        filled += n;
    }
    Ok(true)
}

impl<R: Read> PcapReader<R> {
    /// Reads and validates the global header.
    pub fn new(mut reader: R) -> Result<Self, PcapError> {
        let mut header = [0u8; GLOBAL_HEADER_LEN];
        if !read_full(&mut reader, &mut header)? {
            return Err(PcapError::Truncated);
        }
        let magic = [header[0], header[1], header[2], header[3]];
        let (big_endian, nanos) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (false, false),
            [0xa1, 0xb2, 0xc3, 0xd4] => (true, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => (false, true),
            [0xa1, 0xb2, 0x3c, 0x4d] => (true, true),
            _ => return Err(PcapError::BadMagic),
        };
        let link_type = read_u32(&header[20..24], big_endian);
        Ok(Self {
            reader,
            big_endian,
            nanos,
            link_type,
        })
    }

    pub fn link_type(&self) -> u32 {
        self.link_type
    }

    /// Next packet, or `None` at the end of the capture.
    pub fn next_packet(&mut self) -> Result<Option<Packet>, PcapError> {
        let mut header = [0u8; RECORD_HEADER_LEN];
        if !read_full(&mut self.reader, &mut header)? {
            return Ok(None);
        }
        let secs = read_u32(&header[0..4], self.big_endian);
        let frac = read_u32(&header[4..8], self.big_endian);
        let captured = read_u32(&header[8..12], self.big_endian);
        if captured > MAX_PACKET_LEN {
            return Err(PcapError::PacketTooLarge(captured));
        }
        let mut data = vec![0u8; captured as usize];
        if captured > 0 && !read_full(&mut self.reader, &mut data)? {
            return Err(PcapError::Truncated);
        }
        let divisor = if self.nanos { 1e9 } else { 1e6 };
        let timestamp = f64::from(secs) + f64::from(frac) / divisor;
        Ok(Some(Packet { timestamp, data }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::pcap_file;

    fn sample() -> Vec<u8> {
        pcap_file(LINKTYPE_ETHERNET, &[(1.5, vec![1, 2, 3]), (2.25, vec![4, 5])])
    }

    #[test]
    fn reads_packets_and_timestamps() {
        let bytes = sample();
        let mut reader = PcapReader::new(bytes.as_slice()).unwrap();
        assert_eq!(reader.link_type(), LINKTYPE_ETHERNET);
        let first = reader.next_packet().unwrap().unwrap();
        assert_eq!(first.data, [1, 2, 3]);
        assert!((first.timestamp - 1.5).abs() < 1e-6);
        let second = reader.next_packet().unwrap().unwrap();
        assert_eq!(second.data, [4, 5]);
        assert!((second.timestamp - 2.25).abs() < 1e-6);
        assert!(reader.next_packet().unwrap().is_none());
    }

    #[test]
    fn reads_big_endian_nanosecond_captures() {
        let mut bytes = vec![0xa1, 0xb2, 0x3c, 0x4d];
        bytes.extend_from_slice(&[0, 2, 0, 4]);
        bytes.extend_from_slice(&[0u8; 8]);
        bytes.extend_from_slice(&65535u32.to_be_bytes());
        bytes.extend_from_slice(&LINKTYPE_RAW.to_be_bytes());
        bytes.extend_from_slice(&7u32.to_be_bytes());
        bytes.extend_from_slice(&500_000_000u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.push(9);
        let mut reader = PcapReader::new(bytes.as_slice()).unwrap();
        assert_eq!(reader.link_type(), LINKTYPE_RAW);
        let packet = reader.next_packet().unwrap().unwrap();
        assert!((packet.timestamp - 7.5).abs() < 1e-9);
        assert_eq!(packet.data, [9]);
    }

    #[test]
    fn rejects_bad_magic_and_empty_input() {
        let bad = [0u8; 24];
        assert!(matches!(
            PcapReader::new(bad.as_slice()),
            Err(PcapError::BadMagic)
        ));
        let empty: &[u8] = &[];
        assert!(matches!(PcapReader::new(empty), Err(PcapError::Truncated)));
    }

    #[test]
    fn detects_truncated_records() {
        let mut bytes = sample();
        bytes.truncate(bytes.len() - 1);
        let mut reader = PcapReader::new(bytes.as_slice()).unwrap();
        assert!(reader.next_packet().unwrap().is_some());
        assert!(matches!(reader.next_packet(), Err(PcapError::Truncated)));
    }

    #[test]
    fn rejects_oversized_records() {
        let mut bytes = pcap_file(LINKTYPE_ETHERNET, &[]);
        bytes.extend_from_slice(&[0u8; 8]);
        bytes.extend_from_slice(&(MAX_PACKET_LEN + 1).to_le_bytes());
        bytes.extend_from_slice(&[0u8; 4]);
        let mut reader = PcapReader::new(bytes.as_slice()).unwrap();
        assert!(matches!(
            reader.next_packet(),
            Err(PcapError::PacketTooLarge(_))
        ));
    }

    #[test]
    fn header_only_capture_has_no_packets() {
        let bytes = pcap_file(LINKTYPE_ETHERNET, &[]);
        let mut reader = PcapReader::new(bytes.as_slice()).unwrap();
        assert!(reader.next_packet().unwrap().is_none());
    }
}
