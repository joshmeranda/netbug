use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use num_derive::FromPrimitive;
use num_traits::FromPrimitive;

use crate::error::NbugError;
use crate::protocols::{ProtocolNumber, ProtocolPacket};

#[derive(Clone, Debug, PartialEq)]
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

#[derive(Clone, Debug, FromPrimitive, PartialEq)]
pub enum ServiceType {
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
#[derive(Clone, Debug, PartialEq)]
pub struct Ipv4Packet {
    pub header_length: u16,

    pub service_type: ServiceType,

    pub low_delay: bool,

    pub high_throughput: bool,

    pub high_reliability: bool,

    pub total_length: u16,

    pub identification: u16,

    pub flags: u8,

    pub offset: u16,

    pub ttl: u8,

    pub protocol: ProtocolNumber,

    pub checksum: u16,

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

        let header_length = (data[0] as u16 & 0xF) * 4;

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
#[derive(Clone, Debug, PartialEq)]
pub struct Ipv6Packet {
    pub traffic_class: u8,

    pub flow_label: u32,

    pub payload_length: u16,

    pub next_header: ProtocolNumber,

    pub hop_limit: u8,

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

        if version != 6 {
            return Err(NbugError::Packet(String::from(format!(
                "Wrong version number, expected '6' received: {}",
                version
            ))));
        }

        let mut traffic_class: u8 = 0;
        traffic_class |= data[0] & 0x0 | data[1] >> 4; // last 4 of first byte, and first 4 of second byte

        let mut flow_label: u32 = data[1] as u32 & 0x0f;
        flow_label <<= 8;

        flow_label |= data[2] as u32;
        flow_label <<= 8;

        flow_label |= data[3] as u32;

        let mut length_bytes = [0u8; 2];
        length_bytes.copy_from_slice(&data[4..6]);
        let payload_length = u16::from_be_bytes(length_bytes);

        let next_header =
            FromPrimitive::from_u8(data[6]).expect(&*format!("Invalid or unassigned protocol number {}", data[6]));

        let hop_limit = data[7];

        let mut source_bytes = [0u8; 16];
        source_bytes.copy_from_slice(&data[8..24]);
        let source = Ipv6Addr::from(source_bytes);

        let mut destination_bytes = [0u8; 16];
        destination_bytes.copy_from_slice(&data[24..40]);
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

#[cfg(test)]
mod test {
    use std::convert::{From, TryFrom};
    use std::net::{Ipv4Addr, Ipv6Addr};

    use crate::protocols::ip::{IpPacket, Ipv4Packet, Ipv6Packet, ServiceType};
    use crate::protocols::ProtocolNumber;

    // does not contain any options, if you need options for testing you can build
    // you own packet with this as a template
    const SAMPLE_IPV4_DATA: &[u8] = &[
        0x45, //version && header length
        0x00, // type of service
        0x00, 0x54, // total length
        0xc8, 0x9b, // identification
        0x40, 0x00, // flags and offset
        0x40, // ttl
        0x01, // next header protocol
        0x74, 0x0b, // checksum
        0x7f, 0x00, 0x00, 0x01, // source
        0x7f, 0x00, 0x00, 0x01, // destination
    ];

    const SAMPLE_IPV6_DATA: &[u8] = &[
        0x60, // version && traffic class
        0x02, 0x00, 0xa3, // traffic class && flow label
        0x00, 0x40, // payload length
        0x3a, // next header (icmpv6)
        0x40, // hop limit
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // source
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01, // destination
    ];

    #[test]
    fn test_ip_ok() {
        let ipv4 = IpPacket::try_from(SAMPLE_IPV4_DATA).unwrap();

        if let IpPacket::V6(_) = ipv4 {
            panic!("Expected to find ip v4");
        }

        let ipv6 = IpPacket::try_from(SAMPLE_IPV6_DATA).unwrap();

        if let IpPacket::V4(_) = ipv6 {
            panic!("Expected to find ip v6");
        }
    }

    #[test]
    fn test_ipv4_basic_ok() {
        let actual = Ipv4Packet::try_from(SAMPLE_IPV4_DATA).unwrap();
        let expected = Ipv4Packet {
            header_length:    20,
            service_type:     ServiceType::Routine,
            low_delay:        false,
            high_throughput:  false,
            high_reliability: false,
            total_length:     0x00_54,
            identification:   0xc8_9b,
            flags:            0b0000_0010,
            offset:           0x00,
            ttl:              0x40,
            protocol:         ProtocolNumber::Icmp,
            checksum:         0x74_0b,
            source:           Ipv4Addr::from(0x7f_00_00_01),
            destination:      Ipv4Addr::from(0x7f_00_00_01),
        };

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_ipv4_too_small() {
        if let Ok(_) = Ipv4Packet::try_from(&SAMPLE_IPV4_DATA[1..]) {
            panic!("too few bytes were provided, try_from should have failed");
        }
    }

    #[test]
    fn test_ipv6_basic_ok() {
        let actual = Ipv6Packet::try_from(SAMPLE_IPV6_DATA).unwrap();
        let expected = Ipv6Packet {
            traffic_class:  0x00,
            flow_label:     0x02_00_a3,
            payload_length: 0x40,
            next_header:    ProtocolNumber::Ipv6Icmp,
            hop_limit:      0x40,
            source:         Ipv6Addr::from(0x00_00_00_00_00_00_00_00_00_00_00_00_00_00_00_01),
            destination:    Ipv6Addr::from(0x00_00_00_00_00_00_00_00_00_00_00_00_00_00_00_01),
        };

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_ipv6_too_small() {
        if let Ok(_) = Ipv6Packet::try_from(&SAMPLE_IPV6_DATA[1..]) {
            panic!("too few bytes were provided, try_from should have failed");
        }
    }
}
