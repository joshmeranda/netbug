use std::cmp;
use std::convert::TryFrom;

use crate::error::{NbugError, Result};
use crate::protocols::{ProtocolNumber, ProtocolPacketHeader};

/// An ethernet packet, conforming to either IEE 802.2 or 802.3.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IeeEthernetPacket {
    Ieee8022(Ethernet2Packet),
    Ieee8023(Ethernet3Packet),
}

impl IeeEthernetPacket {
    const MAC_BYTES: usize = 6;
    const LENGTH_BYTES: usize = 2;
}

impl From<Ethernet2Packet> for IeeEthernetPacket {
    fn from(ethernet: Ethernet2Packet) -> Self { Self::Ieee8022(ethernet) }
}

impl From<Ethernet3Packet> for IeeEthernetPacket {
    fn from(ethernet: Ethernet3Packet) -> Self { Self::Ieee8023(ethernet) }
}

impl TryFrom<&[u8]> for IeeEthernetPacket {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<IeeEthernetPacket> {
        let length_bytes: [u8; 2] = [data[12], data[13]];
        let length = u16::from_be_bytes(length_bytes);

        if length > 1500 {
            Ok(IeeEthernetPacket::Ieee8022(Ethernet2Packet::try_from(data)?))
        } else {
            Ok(IeeEthernetPacket::Ieee8023(Ethernet3Packet::try_from(data)?))
        }
    }
}

impl PartialEq<Ethernet2Packet> for IeeEthernetPacket {
    fn eq(&self, other: &Ethernet2Packet) -> bool {
        match self {
            IeeEthernetPacket::Ieee8022(ethernet) => ethernet == other,
            IeeEthernetPacket::Ieee8023(_) => false,
        }
    }
}

impl PartialEq<Ethernet3Packet> for IeeEthernetPacket {
    fn eq(&self, other: &Ethernet3Packet) -> bool {
        match self {
            IeeEthernetPacket::Ieee8022(_) => false,
            IeeEthernetPacket::Ieee8023(ethernet) => ethernet == other,
        }
    }
}

impl ProtocolPacketHeader for IeeEthernetPacket {
    fn header_length(&self) -> usize {
        match self {
            IeeEthernetPacket::Ieee8022(packet) => packet.header_length(),
            IeeEthernetPacket::Ieee8023(packet) => packet.header_length(),
        }
    }

    fn protocol_type(&self) -> ProtocolNumber {
        match self {
            IeeEthernetPacket::Ieee8022(packet) => packet.protocol_type(),
            IeeEthernetPacket::Ieee8023(packet) => packet.protocol_type(),
        }
    }
}

/// The ethernet packet for IEE 802.2true.
#[derive(Copy, Clone, Debug, Eq)]
pub struct Ethernet2Packet {
    pub destination: [u8; 6],

    pub source: [u8; 6],

    pub protocol: ProtocolNumber,
}

impl Ethernet2Packet {
    /// The minimum amount of bytes of data necessary to deserialize an
    /// [Ethernet2] using [try_from].
    const MIN_BYTES: usize = IeeEthernetPacket::MAC_BYTES * 2 + IeeEthernetPacket::LENGTH_BYTES;

    pub fn new(destination: [u8; 6], source: [u8; 6], protocol: ProtocolNumber) -> Ethernet2Packet {
        Ethernet2Packet {
            destination,
            source,
            protocol,
        }
    }

    pub fn ethernet_from_u16(value: u16) -> Result<ProtocolNumber> {
        match value {
            0x08_00 => Ok(ProtocolNumber::Ipv4),
            0x86_dd => Ok(ProtocolNumber::Ipv6),
            _ => Err(NbugError::Packet(format!(
                "unsupported ethernet protocol type value '{}'",
                value
            ))),
        }
    }
}

impl TryFrom<&[u8]> for Ethernet2Packet {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Ethernet2Packet> {
        if data.len() < Self::MIN_BYTES {
            return Err(NbugError::Packet(format!(
                "Too few bytes, expected at least {}",
                Self::MIN_BYTES
            )));
        }

        let mut destination = [0u8; 6];
        let mut source = [0u8; 6];

        destination.copy_from_slice(&data[0..6]);
        source.copy_from_slice(&data[6..12]);

        let mut protocol_bytes = [0u8; 2];
        protocol_bytes.copy_from_slice(&data[12..14]);

        let protocol = Ethernet2Packet::ethernet_from_u16(u16::from_be_bytes(protocol_bytes))?;

        Ok(Ethernet2Packet {
            destination,
            source,
            protocol,
        })
    }
}

impl PartialEq<Ethernet2Packet> for Ethernet2Packet {
    fn eq(&self, other: &Ethernet2Packet) -> bool {
        self.destination == other.destination && self.source == other.source && self.protocol == other.protocol
    }
}

impl ProtocolPacketHeader for Ethernet2Packet {
    fn header_length(&self) -> usize { Self::MIN_BYTES }

    fn protocol_type(&self) -> ProtocolNumber {
        ProtocolNumber::Ethernet // todo: this is a temporary value which is
                                 // VERY wrong until a
                                 //   better fix can be implemented
    }
}

/// The ethernet packet for IEE 802.3
#[derive(Copy, Clone, Debug, Eq)]
pub struct Ethernet3Packet {
    pub destination: [u8; 6],

    pub source: [u8; 6],

    pub length: usize,

    frame_check_sequence: u32,
}

impl Ethernet3Packet {
    const MIN_DATA_BYTES: usize = 46;
    const FRAME_CHECK_SEQUENCE_BYTES: usize = 4;

    const MIN_BYTES: usize = IeeEthernetPacket::MAC_BYTES * 2
        + IeeEthernetPacket::LENGTH_BYTES
        + Self::MIN_DATA_BYTES
        + Self::FRAME_CHECK_SEQUENCE_BYTES;

    pub fn new(destination: [u8; 6], source: [u8; 6], length: usize, fcs: u32) -> Ethernet3Packet {
        Ethernet3Packet {
            destination,
            source,
            length,
            frame_check_sequence: fcs,
        }
    }
}

impl TryFrom<&[u8]> for Ethernet3Packet {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Ethernet3Packet> {
        if data.len() < Self::MIN_BYTES {
            return Err(NbugError::Packet(format!(
                "Too few bytes, expected at least {}",
                Self::MIN_BYTES
            )));
        }

        let mut destination = [0u8; 6];
        let mut source = [0u8; 6];

        destination.copy_from_slice(&data[0..6]);
        source.copy_from_slice(&data[6..12]);

        let mut protocol_bytes = [0u8; 2];
        protocol_bytes.copy_from_slice(&data[12..14]);

        // todo: cover more protocol
        let length = u16::from_be_bytes(protocol_bytes) as usize;
        let padding = if Self::MIN_DATA_BYTES > length {
            Self::MIN_DATA_BYTES - length
        } else {
            0
        };

        // ensure there is enough data to fit the data and frame sequence
        if data.len() < Self::MIN_BYTES + length as usize - Self::MIN_DATA_BYTES {
            return Err(NbugError::Packet(format!(
                "Too few bytes, expected at least {}",
                Self::MIN_BYTES + length as usize - Self::MIN_BYTES
            )));
        }

        let fcs_offset = IeeEthernetPacket::MAC_BYTES * 2 + IeeEthernetPacket::LENGTH_BYTES + length + padding;

        let mut fcs_bytes = [0u8; 4];
        fcs_bytes.copy_from_slice(&data[fcs_offset..fcs_offset + 4]);
        let frame_check_sequence = u32::from_be_bytes(fcs_bytes);

        Ok(Ethernet3Packet {
            destination,
            source,
            length,
            frame_check_sequence,
        })
    }
}

impl PartialEq<Ethernet3Packet> for Ethernet3Packet {
    fn eq(&self, other: &Ethernet3Packet) -> bool {
        self.destination == other.destination
            && self.source == other.source
            && self.length == other.length
            && self.frame_check_sequence == other.frame_check_sequence
    }
}

impl ProtocolPacketHeader for Ethernet3Packet {
    fn header_length(&self) -> usize { Self::MIN_BYTES }

    fn protocol_type(&self) -> ProtocolNumber {
        ProtocolNumber::Ethernet // todo: this is a temporary value which is
                                 //   VERY wrong until a better fix can be
                                 //   implemented
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use crate::protocols::ethernet::{Ethernet2Packet, Ethernet3Packet, IeeEthernetPacket};
    use crate::protocols::ProtocolNumber;

    #[test]
    fn iee_ethernet2_from_raw_ok() {
        let raw: &[u8] = &[
            0, 1, 2, 3, 4, 5, // destination MAC
            5, 4, 3, 2, 1, 0, // source MAC
            0x08, 0x_00, // type (Iv4)
        ];

        assert_eq!(
            IeeEthernetPacket::Ieee8022(Ethernet2Packet::new(
                [0, 1, 2, 3, 4, 5],
                [5, 4, 3, 2, 1, 0],
                ProtocolNumber::Ipv4
            )),
            IeeEthernetPacket::try_from(raw).unwrap()
        );
    }

    #[test]
    fn iee_ethernet3_from_raw_ok() {
        let raw: &[u8] = &[
            0, 1, 2, 3, 4, 5, // destination MAC
            5, 4, 3, 2, 1, 0, // source MAC
            0, 24, // length
            0, 1, 2, 3, 4, 5, 6, 7, // payload data
            8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // frame check sequence
        ];

        assert_eq!(
            IeeEthernetPacket::Ieee8023(Ethernet3Packet::new([0, 1, 2, 3, 4, 5], [5, 4, 3, 2, 1, 0], 24, 1)),
            IeeEthernetPacket::try_from(raw).unwrap()
        );
    }

    #[test]
    fn ethernet2_from_raw_ok() {
        let raw: &[u8] = &[
            0, 1, 2, 3, 4, 5, // destination MAC
            5, 4, 3, 2, 1, 0, // source MAC
            0x08, 0x_00, // type (Iv4)
        ];

        assert_eq!(
            Ethernet2Packet::new([0, 1, 2, 3, 4, 5], [5, 4, 3, 2, 1, 0], ProtocolNumber::Ipv4),
            Ethernet2Packet::try_from(raw).unwrap()
        );
    }

    #[test]
    fn ethernet2_from_raw_too_small() {
        let raw: &[u8] = &[
            0, 1, 2, 3, 4, // destination MAC (too small)
            5, 4, 3, 2, 1, 0, // source MAC
            0x08, 0x_00, // type (Iv4)
        ];

        if let Ok(_) = Ethernet2Packet::try_from(raw) {
            panic!("too few bytes were provided, try_from should have failed");
        }
    }

    #[test]
    fn ethernet3_from_raw_empty_payload_ok() {
        let raw: &[u8] = &[
            0, 1, 2, 3, 4, 5, // destination MAC
            5, 4, 3, 2, 1, 0, // source MAC
            0, 0, // length
            0, 0, 0, 0, 0, 0, 0, 0, // payload data
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 1, // frame check sequence
        ];

        assert_eq!(
            Ethernet3Packet::new([0, 1, 2, 3, 4, 5], [5, 4, 3, 2, 1, 0], 0, 1),
            Ethernet3Packet::try_from(raw).unwrap()
        );
    }

    #[test]
    fn ethernet3_from_raw_half_full_ok() {
        let raw: &[u8] = &[
            0, 1, 2, 3, 4, 5, // destination MAC
            5, 4, 3, 2, 1, 0, // source MAC
            0, 24, // length
            0, 1, 2, 3, 4, 5, 6, 7, // payload data
            8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, // frame check sequence
        ];

        assert_eq!(
            Ethernet3Packet::new([0, 1, 2, 3, 4, 5], [5, 4, 3, 2, 1, 0], 24, 1),
            Ethernet3Packet::try_from(raw).unwrap()
        );
    }

    #[test]
    fn ethernet3_from_raw_exactly_full_ok() {
        let raw: &[u8] = &[
            0, 1, 2, 3, 4, 5, // destination MAC
            5, 4, 3, 2, 1, 0, // source MAC
            0, 46, // length
            0, 1, 2, 3, 4, 5, 6, 7, // payload data
            8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
            35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 0, 0, 0, 1, // frame check sequence
        ];

        assert_eq!(
            Ethernet3Packet::new([0, 1, 2, 3, 4, 5], [5, 4, 3, 2, 1, 0], 46, 1),
            Ethernet3Packet::try_from(raw).unwrap()
        );
    }

    #[test]
    fn ethernet3_from_raw_overfull_payload_ok() {
        let raw: &[u8] = &[
            0, 1, 2, 3, 4, 5, // destination MAC
            5, 4, 3, 2, 1, 0, // source MAC
            0, 48, // length
            0, 1, 2, 3, 4, 5, 6, 7, // payload data
            8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
            35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 0, 0, 0, 1, // frame check sequence
        ];

        assert_eq!(
            Ethernet3Packet::new([0, 1, 2, 3, 4, 5], [5, 4, 3, 2, 1, 0], 48, 1),
            Ethernet3Packet::try_from(raw).unwrap()
        );
    }

    #[test]
    fn ethernet_from_raw_too_small() {
        let raw: &[u8] = &[
            0, 1, 2, 3, 4, // destination MAC (too small)
            5, 4, 3, 2, 1, 0, // source MAC
            0, 0, // length
            0, 0, 0, 0, 0, 0, 0, 0, // payload data
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 1, // frame check sequence
        ];

        if let Ok(n) = Ethernet3Packet::try_from(raw) {
            panic!("too few bytes were provided, try_from should have failed");
        }
    }
}
