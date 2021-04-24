use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::error::NbugError;
use crate::protocols::{ProtocolNumber, ProtocolPacket};

pub enum IpPacket {
    V4(Ipv4Packet),
    V6(Ipv6Packet),
}

impl IpPacket {
    pub fn source(&self) -> IpAddr {
        match self {
            IpPacket::V4(packet) => IpAddr::from(packet.source),
            IpPacket::V6(packet) => IpAddr::from(packet.source),
        }
    }

    pub fn destination(&self) -> IpAddr {
        match self {
            IpPacket::V4(packet) => IpAddr::from(packet.destination),
            IpPacket::V6(packet) => IpAddr::from(packet.destination),
        }
    }

    pub fn protocol(&self) -> ProtocolNumber {
        match self {
            IpPacket::V4(packet) => packet.protocol,
            IpPacket::V6(packet) => packet.next_header,
        }
    }
}

impl From<Ipv4Packet> for IpPacket {
    fn from(value: Ipv4Packet) -> Self { IpPacket::V4(value) }
}

impl From<Ipv6Packet> for IpPacket {
    fn from(value: Ipv6Packet) -> Self { IpPacket::V6(value) }
}

impl TryFrom<&[u8]> for IpPacket {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let version = data[0] >> 4;

        match version {
            4 => Ok(IpPacket::V4(Ipv4Packet::try_from(data)?)),
            6 => Ok(IpPacket::V6(Ipv6Packet::try_from(data)?)),
            version => Err(NbugError::Packet(String::from(format!(
                "Invalid Ip packet version number '{}'",
                version
            )))),
        }
    }
}

#[derive(FromPrimitive)]
enum ServiceType {
    Routine             = 0b000,
    Priority            = 0b001,
    Immediate           = 0b010,
    Flash               = 0b011,
    FlashOverride       = 0b100,
    CriticEcp           = 0b101,
    InterNetworkControl = 0b110,
    NetworkControl      = 0b111,
}

/// The IPv4 Packet header as specified in [RFC 791](https://tools.ietf.org/html/rfc791#section-3.1).
pub struct Ipv4Packet {
    header_length: u16,

    service_type: ServiceType,

    low_delay: bool,

    high_throughput: bool,

    high_reliability: bool,

    total_length: u16,

    identification: u16,

    flags: u8,

    offset: u16,

    ttl: u8,

    pub protocol: ProtocolNumber,

    checksum: u16,

    pub source: Ipv4Addr,

    pub destination: Ipv4Addr,
}

impl Ipv4Packet {
    /// Minimum amount of bytes required to parse a full [Ipv4Packet], this
    /// value is the same length as a packet with no options.
    pub const MIN_BYTES: usize = 20; // main header data
}

impl TryFrom<&[u8]> for Ipv4Packet {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < Ipv4Packet::MIN_BYTES {
            return Err(NbugError::Packet(String::from(format!(
                "Too few bytes, expected at least {}",
                Ipv4Packet::MIN_BYTES
            ))));
        };

        let version = data[0] >> 4;

        if version != 4 {
            return Err(NbugError::Packet(String::from(format!(
                "Wrong version number, expected '4' received: {}",
                version
            ))));
        }

        let header_length = (data[0] as u16 & 0xF) * 32 / 8;

        if header_length as usize != Ipv4Packet::MIN_BYTES {
            return Err(NbugError::Packet(String::from(format!(
                "Ipv4 options are not yet supported"
            ))));
        }

        let service_type = FromPrimitive::from_u8(data[1] & 0b0111).unwrap();
        let low_delay = data[1] & 0b0000_1000 == 0b0000_1000;
        let high_throughput = data[1] & 0b0001_0000 == 0b0001_0000;
        let high_reliability = data[1] & 0b0010_0000 == 0b0010_0000;

        let mut total_length_bytes = [0u8; 2];
        total_length_bytes.copy_from_slice(&data[2..4]);
        let total_length = u16::from_be_bytes(total_length_bytes);

        let mut identification_bytes = [0u8; 2];
        identification_bytes.copy_from_slice(&data[4..6]);
        let identification: u16 = u16::from_be_bytes(identification_bytes);

        let flags = data[6] >> 5;

        let mut offset_bytes = [0u8; 2];
        offset_bytes.copy_from_slice(&data[6..8]);
        offset_bytes[0] &= 0b0001_1111u8;
        let offset = u16::from_be_bytes(offset_bytes);

        let ttl = data[8];

        let protocol =
            FromPrimitive::from_u8(data[9]).expect(&*format!("Invalid or unassigned protocol number {}", data[9]));

        let mut checksum_bytes = [0u8; 2];
        checksum_bytes.copy_from_slice(&data[10..12]);
        let checksum = u16::from_be_bytes(checksum_bytes);

        let mut source_bytes = [0u8; 4];
        source_bytes.copy_from_slice(&data[12..16]);
        let source = Ipv4Addr::from(source_bytes);

        let mut destination_bytes = [0u8; 4];
        destination_bytes.copy_from_slice(&data[16..20]);
        let destination = Ipv4Addr::from(destination_bytes);

        Ok(Ipv4Packet {
            header_length,
            service_type,
            low_delay,
            high_throughput,
            high_reliability,
            total_length,
            identification,
            flags,
            offset,
            ttl,
            protocol,
            checksum,
            source,
            destination,
        })
    }
}

/// Ipv6 Packet Header as specified in [RFC 8200](https://tools.ietf.org/html/rfc8200#section-3).
/// todo: support for extension headers
pub struct Ipv6Packet {
    traffic_class: u8,

    flow_label: u32,

    payload_length: u16,

    pub next_header: ProtocolNumber,

    hop_limit: u8,

    pub source: Ipv6Addr,

    pub destination: Ipv6Addr,
}

impl Ipv6Packet {
    pub const MIN_BYTES: usize = 40;
}

impl TryFrom<&[u8]> for Ipv6Packet {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let version = data[0] >> 4;

        if version != 4 {
            return Err(NbugError::Packet(String::from(format!(
                "Wrong version number, expected '6' received: {}",
                version
            ))));
        }

        let mut traffic_class: u8 = 0;
        traffic_class |= data[0] | data[1] >> 4; // last 4 of first byte, and first 4 of second byte

        let mut flow_label: u32 = 0;
        flow_label |= data[1] as u32 & 0x0Fu32; // add last 4 bytes of previous byte
        flow_label <<= 16;

        flow_label &= data[2] as u32;
        flow_label <<= 8;

        flow_label &= data[3] as u32;

        let mut length_bytes = [0u8; 2];
        length_bytes.copy_from_slice(&data[4..6]);
        let payload_length = u16::from_be_bytes(length_bytes);

        let next_header =
            FromPrimitive::from_u8(data[6]).expect(&*format!("Invalid or unassigned protocol number {}", data[6]));

        let hop_limit = data[7];

        let mut source_bytes = [0u8; 16];
        source_bytes.copy_from_slice(&data[8..12]);
        let source = Ipv6Addr::from(source_bytes);

        let mut destination_bytes = [0u8; 16];
        destination_bytes.copy_from_slice(&data[12..16]);
        let destination = Ipv6Addr::from(destination_bytes);

        Ok(Ipv6Packet {
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            source,
            destination,
        })
    }
}
