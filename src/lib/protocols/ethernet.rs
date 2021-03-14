use crate::protocols::Protocol;
use std::convert::TryFrom;
use crate::error::{NbugError, Result};

/// An ethernet packet, conforming to either IEE 802.2 or *02.3.
enum IeeEthernet {
    Ieee802_2(Ethernet2),
    Ieee802_3(Ethernet3),
}

impl IeeEthernet {
    const PREAMBLE_BYTES: usize = 8;
    const MAC_BYTES: usize = 6;
    const LENGTH_BYTES: usize = 2;
}

impl From<Ethernet2> for IeeEthernet {
    fn from(ethernet: Ethernet2) -> Self {
        Self::Ieee802_2(ethernet)
    }
}

impl From<Ethernet3> for IeeEthernet {
    fn from(ethernet: Ethernet3) -> Self {
        Self::Ieee802_3(ethernet)
    }
}

impl TryFrom<&[u8]> for IeeEthernet {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<IeeEthernet> {
        let length_bytes: [u8; 2] = [data[20], data[21]];
        let length = u16::from_be_bytes(length_bytes);

        if length > 1500 {
            Ok(IeeEthernet::Ieee802_2(Ethernet2::try_from(data)?))
        } else {
            Ok(IeeEthernet::Ieee802_3(Ethernet3::try_from(data)?))
        }
    }
}

/// The ethernet packet for IEE 802.2
struct Ethernet2 {
    destination: [u8; 6],

    source: [u8; 6],

    protocol: Protocol,
}

impl Ethernet2 {
    const IPV4_PROTO_VL: u16 = 0x08_00;
    const IPV6_PROTO_VL: u16 = 0x86_dd;

    /// The minimum amount of bytes of data necessary to deserialize an [Ethernet2] using [try_from].
    const MIN_BYTES: usize = IeeEthernet::MAC_BYTES * 2 + IeeEthernet::LENGTH_BYTES;
}

impl TryFrom<&[u8]> for Ethernet2 {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Ethernet2> {
        if data.len() < Self::MIN_BYTES {
            return Err(NbugError::Packet(format!("Too few bytes, expected at least {}", Self::MIN_BYTES)));
        }

        let mut destination = [0u8; 6];
        let mut source = [0u8; 6];

        destination.copy_from_slice(&data[8..14]);
        source.copy_from_slice(&data[14..20]);

        let mut protocol_bytes = [0u8; 2];
        protocol_bytes.copy_from_slice(&data[20..22]);

        // todo: cover more protocol
        let protocol = match u16::from_be_bytes(protocol_bytes) {
            Ethernet2::IPV4_PROTO_VL => Protocol::Ip,
            Ethernet2::IPV6_PROTO_VL => Protocol::Ipv6,
            _ => Protocol::Unknown
        };

        Ok(Ethernet2 { destination, source, protocol })
    }
}

/// The ethernet packet for IEE 802.3
struct Ethernet3 {
    destination: [u8; 6],

    source: [u8; 6],

    length: u16,
}

impl Ethernet3 {
    const MIN_DATA_BYTES: usize = 46;
    const FRAME_CHECK_SEQUENCE_BYTES: usize = 2;

    const MIN_BYTES: usize = IeeEthernet::MAC_BYTES * 2 + IeeEthernet::LENGTH_BYTES +
        Self::MIN_DATA_BYTES + Self::FRAME_CHECK_SEQUENCE_BYTES;
}

impl TryFrom<&[u8]> for Ethernet3 {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Ethernet3> {
        if data.len() < Self::MIN_BYTES {
            return Err(NbugError::Packet(format!("Too few bytes, expected at least {}", Self::MIN_BYTES)));
        }

        let mut destination = [0u8; 6];
        let mut source = [0u8; 6];

        destination.copy_from_slice(&data[8..14]);
        source.copy_from_slice(&data[14..20]);

        let mut protocol_bytes = [0u8; 2];
        protocol_bytes.copy_from_slice(&data[20..22]);

        // todo: cover more protocol
        let length = u16::from_be_bytes(protocol_bytes);

        // ensure there is enough data to fit the data and frame sequence
        if data.len() < Self::MIN_BYTES + length as usize - Self::MIN_BYTES {
            return Err(NbugError::Packet(format!("Too few bytes, expected at least {}", Self::MIN_BYTES + length as usize - Self::MIN_BYTES)));
        }

        Ok(Ethernet3 { destination, source, length })
    }
}