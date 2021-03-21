use std::convert::TryFrom;
use std::net::{Ipv4Addr, Ipv6Addr};

use toml::ser::tables_last;

use crate::error::NbugError;
use crate::protocols::ProtocolType;

enum IpPacket {
    V4(Ipv4Packet),
    V6(Ipv6Packet),
}

enum ServiceType {
    Routine,
    Priority,
    Immediate,
    Flash,
    FlashOverride,
    CriticEcp,
    InternetworkControl,
    NetworkControl,
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
            _ => Err(NbugError::Packet(String::from(format!(
                "invalid  ip  service type value '{}'",
                value
            )))),
        }
    }
}

/// The IPv4 Packet header as specified in [RFC 791](https://tools.ietf.org/html/rfc791#section-3.1).
struct Ipv4Packet {
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
        + 15; // padding to ensure alignment on 32 byte boundary
}

impl TryFrom<&[u8]> for Ipv4Packet {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < Ipv4Packet::MIN_BYTES {
            return Err(NbugError::Packet(String::from(format!(
                "Too few bytes, expected at least {}",
                Ipv4Packet::MIN_BYTES
            ))));
        }

        let version = data[0] >> 4;

        if version != 4 {
            return Err(NbugError::Packet(String::from(format!(
                "Wrong version number, expected '4' received: {}",
                version
            ))));
        }

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
            destination,
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

    destination: Ipv6Addr,
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

        let next_header = ProtocolType::try_from(data[6])?;
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
