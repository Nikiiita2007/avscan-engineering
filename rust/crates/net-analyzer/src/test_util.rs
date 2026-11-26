//! Helpers shared by unit tests: temp directories and packet builders.

use std::fs;
use std::path::{Path, PathBuf};

/// A temporary directory that is removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let name = format!("net_analyzer_{tag}_{}", std::process::id());
        let path = std::env::temp_dir().join(name);
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create temp dir");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn write_bytes(&self, rel: &str, content: &[u8]) {
        fs::write(self.0.join(rel), content).expect("write file");
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Builds a classic little-endian pcap file (microsecond timestamps).
pub fn pcap_file(link_type: u32, packets: &[(f64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[0xd4, 0xc3, 0xb2, 0xa1]);
    out.extend_from_slice(&2u16.to_le_bytes());
    out.extend_from_slice(&4u16.to_le_bytes());
    out.extend_from_slice(&0i32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&65535u32.to_le_bytes());
    out.extend_from_slice(&link_type.to_le_bytes());
    for (ts, data) in packets {
        let ts = *ts;
        let secs = ts as u32;
        let micros = ((ts - f64::from(secs)) * 1e6).round() as u32;
        let len = data.len() as u32;
        out.extend_from_slice(&secs.to_le_bytes());
        out.extend_from_slice(&micros.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(data);
    }
    out
}

pub fn ipv4_packet(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = (20 + payload.len()) as u16;
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0]);
    packet.push(64);
    packet.push(proto);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(payload);
    packet
}

pub fn udp_segment(src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let len = (8 + payload.len()) as u16;
    let mut segment = Vec::new();
    segment.extend_from_slice(&src_port.to_be_bytes());
    segment.extend_from_slice(&dst_port.to_be_bytes());
    segment.extend_from_slice(&len.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    segment
}

pub fn tcp_segment(src_port: u16, dst_port: u16, flags: u8) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&src_port.to_be_bytes());
    segment.extend_from_slice(&dst_port.to_be_bytes());
    segment.extend_from_slice(&[0u8; 8]);
    segment.push(0x50);
    segment.push(flags);
    segment.extend_from_slice(&[0u8; 6]);
    segment
}

pub fn ethernet_frame(ip_packet: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; 12];
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(ip_packet);
    frame
}

pub fn udp_frame(src: [u8; 4], dst: [u8; 4], ports: (u16, u16), payload: &[u8]) -> Vec<u8> {
    let segment = udp_segment(ports.0, ports.1, payload);
    ethernet_frame(&ipv4_packet(17, src, dst, &segment))
}

pub fn tcp_frame(src: [u8; 4], dst: [u8; 4], ports: (u16, u16), flags: u8) -> Vec<u8> {
    let segment = tcp_segment(ports.0, ports.1, flags);
    ethernet_frame(&ipv4_packet(6, src, dst, &segment))
}

/// A DNS message with one question.
pub fn dns_message(name: &str, qtype: u16, response: bool, rcode: u8) -> Vec<u8> {
    let flags: u16 = if response {
        0x8180 | u16::from(rcode)
    } else {
        0x0100
    };
    let mut message = vec![0x12, 0x34];
    message.extend_from_slice(&flags.to_be_bytes());
    message.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        message.push(label.len() as u8);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&[0, 1]);
    message
}
