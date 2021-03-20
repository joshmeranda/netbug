use crate::protocols::ProtocolType;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::convert::TryFrom;
use crate::error::NbugError;

enum IpPacket {
    V4(Ipv4Packet),
    V6(Ipv6Packet)
}

enum ServiceType {
    Routine,
    Priority,
    Immediate,
    Flash,
    FlashOverride,
    CriticEcp,
    InternetworkControl,
    NetworkControl
}

impl TryFrom<u8> for ServiceType {
    type Error = NbugError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0b0000_0000u8 => Ok(ServiceType::Routine),
            0b0000_0001u8 => Ok(ServiceType::Priority),
            0b0000_0010u8 => Ok(ServiceType::Immediate),
            0b0000_0011u8 => Ok(ServiceType::Flash),
            0b0000_0100u8 => Ok(ServiceType::FlashOverride),
            0b0000_0101u8 => Ok(ServiceType::CriticEcp),
            0b0000_0110u8 => Ok(ServiceType::InternetworkControl),
            0b0000_0111u8 => Ok(ServiceType::NetworkControl),
            _ => Err(NbugError::Packet(String::from(format!("invalid  ip  service type value '{}'", value))))
        }
    }
}

/// The IPv4 Packet header as specified in [RFC 791](https://tools.ietf.org/html/rfc791#section-3.1).
struct Ipv4Packet {
    version: u8,

    header_length: u8,

    service_type: ServiceType,

    total_length: u16,

    identification: u16,

    flags: u8,

    offset: u16,

    ttl: u8,

    protocol: ProtocolType,

    checksum: u16,

    source: Ipv4Addr,

    destination: Ipv4Addr,
}

impl Ipv4Packet {
    const MIN_BYTES: usize = 48 // main header data
        + 1                     // minimum no options packet
        + 17;                   // padding to ensure alignment on 32 byte boundary
}

impl TryFrom<&[u8]> for Ipv4Packet {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < Ipv4Packet::MIN_BYTES {
            return Err(NbugError::Packet(String::from(format!("Too few bytes, expected at least {}", Ipv4Packet::MIN_BYTES))))
        }

        let version = data[0] >> 4;
        let header_length = data[0] & 0xF;
        let service_type = ServiceType::try_from(data[1])?;

        let mut total_length_bytes = [0u8; 2];
        total_length_bytes.copy_from_slice(&data[3..5]);
        let total_length = u16::from_be_bytes(total_length_bytes);

        let mut identification_bytes = [0u8; 2];
        identification_bytes.copy_from_slice(&data[5..6]);
        let identification: u16 = u16::from_be_bytes(identification_bytes);

        let flags = data[6] >> 5;

        let mut offset_bytes = [0u8; 2];
        offset_bytes.copy_from_slice(&data[6..8]);
        offset_bytes[0] &= 0b0001_1111u8;
        let offset = u16::from_be_bytes(offset_bytes);

        let ttl = data[8];
        let protocol = ProtocolType::try_from(data[9])?;

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
            version,
            header_length,
            service_type,
            total_length,
            identification,
            flags,
            offset,
            ttl,
            protocol,
            checksum,
            source,
            destination
        })
    }
}

/// Ipv6 Packet Header as specified in [RFC 8200](https://tools.ietf.org/html/rfc8200#section-3).
///
/// todo: support for extension headers
struct Ipv6Packet {
    // todo: consider making enum
    traffic_class: u8,

    flow_label: u32,

    payload_length: u16,

    next_header: ProtocolType,

    hop_limit: u8,

    source: Ipv6Addr,

    destination: Ipv6Addr
}