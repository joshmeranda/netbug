use crate::protocols::ProtocolType;
use std::convert::TryFrom;
use crate::error::{NbugError, Result};
use std::cmp;

/// An ethernet packet, conforming to either IEE 802.2 or *02.3.
#[derive(Copy, Clone, Eq, PartialEq)]
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

impl PartialEq<Ethernet2> for IeeEthernet {
    fn eq(&self, other: &Ethernet2) -> bool {
        match self {
            IeeEthernet::Ieee802_2(ethernet) => ethernet == other,
            IeeEthernet::Ieee802_3(_) => false
        }
    }
}

impl PartialEq<Ethernet3> for IeeEthernet {
    fn eq(&self, other: &Ethernet3) -> bool {
        match self {
            IeeEthernet::Ieee802_2(_) => false,
            IeeEthernet::Ieee802_3(ethernet) => ethernet == other
        }
    }
}

/// The ethernet packet for IEE 802.2true.
#[derive(Copy, Clone, Debug, Eq)]
pub struct Ethernet2 {
    destination: [u8; 6],

    source: [u8; 6],

    protocol: ProtocolType,
}

impl Ethernet2 {
    /// The minimum amount of bytes of data necessary to deserialize an [Ethernet2] using [try_from].
    const MIN_BYTES: usize = IeeEthernet::PREAMBLE_BYTES + IeeEthernet::MAC_BYTES * 2 + IeeEthernet::LENGTH_BYTES;

    pub fn new(destination: [u8; 6], source: [u8; 6], protocol: ProtocolType) -> Ethernet2 {
        Ethernet2 { destination, source, protocol }
    }

    pub fn ethernet_from_u16(value: u16) -> Result<ProtocolType> {
        match value {
            0x08_00 => Ok(ProtocolType::Ipv4),
            0x86_dd => Ok(ProtocolType::Ipv6),
            _ => Err(NbugError::Packet(format!("unsupported ethernet protocol type value '{}'", value)))
        }
    }
}

impl TryFrom<&[u8]> for Ethernet2 {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Ethernet2> {
        if data.len() < Self::MIN_BYTES {
            return Err(NbugError::Packet(format!("Too few bytes, expected at least {}", Self::MIN_BYTES)));
        }
        let n = Self::MIN_BYTES;

        let mut destination = [0u8; 6];
        let mut source = [0u8; 6];

        destination.copy_from_slice(&data[8..14]);
        source.copy_from_slice(&data[14..20]);

        let mut protocol_bytes = [0u8; 2];
        protocol_bytes.copy_from_slice(&data[20..22]);

        let protocol = Ethernet2::ethernet_from_u16(u16::from_be_bytes(protocol_bytes))?;

        Ok(Ethernet2 { destination, source, protocol })
    }
}

impl PartialEq<Ethernet2> for Ethernet2 {
    fn eq(&self, other: &Ethernet2) -> bool {
        self.destination == other.destination &&
            self.source == other.source &&
            self.protocol == other.protocol
    }
}

/// The ethernet packet for IEE 802.3
#[derive(Copy, Clone, Debug, Eq)]
struct Ethernet3 {
    destination: [u8; 6],

    source: [u8; 6],

    length: usize,

    frame_check_sequence: u32
}

impl Ethernet3 {
    const MIN_DATA_BYTES: usize = 46;
    const FRAME_CHECK_SEQUENCE_BYTES: usize = 4;

    const MIN_BYTES: usize = IeeEthernet::PREAMBLE_BYTES + IeeEthernet::MAC_BYTES * 2 +
        IeeEthernet::LENGTH_BYTES + Self::MIN_DATA_BYTES + Self::FRAME_CHECK_SEQUENCE_BYTES;

    pub fn new(destination: [u8; 6], source: [u8; 6], length: usize, fcs: u32) -> Ethernet3 {
        Ethernet3 {
            destination,
            source,
            length,
            frame_check_sequence: fcs
        }
    }
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
        let length = u16::from_be_bytes(protocol_bytes) as usize;
        let padding = if Self::MIN_DATA_BYTES > length {
            Self::MIN_DATA_BYTES - length
        } else {
            0
        };

        // ensure there is enough data to fit the data and frame sequence
        if data.len() < Self::MIN_BYTES + length as usize - Self::MIN_DATA_BYTES {
            return Err(NbugError::Packet(format!("Too few bytes, expected at least {}", Self::MIN_BYTES + length as usize - Self::MIN_BYTES)));
        }

        let fcs_offset = IeeEthernet::PREAMBLE_BYTES + IeeEthernet::MAC_BYTES * 2 +
            IeeEthernet::LENGTH_BYTES + length + padding;

        let n = IeeEthernet::PREAMBLE_BYTES + IeeEthernet::MAC_BYTES * 2 +
            IeeEthernet::LENGTH_BYTES;

        let mut fcs_bytes = [0u8; 4];
        fcs_bytes.copy_from_slice(&data[fcs_offset..fcs_offset + 4]);
        let frame_check_sequence = u32::from_be_bytes(fcs_bytes);

        Ok(Ethernet3 { destination, source, length, frame_check_sequence})
    }
}

impl PartialEq<Ethernet3> for Ethernet3 {
    fn eq(&self, other: &Ethernet3) -> bool {
        self.destination == other.destination &&
            self.source == other.source &&
            self.length == other.length &&
            self.frame_check_sequence == other.frame_check_sequence
    }
}

#[cfg(test)]
mod test {
    use crate::protocols::ethernet::{Ethernet2, Ethernet3};
    use std::convert::TryFrom;
    use crate::protocols::ProtocolType;

    #[test]
    fn ethernet2_from_raw_ok() {
        let raw: &[u8] = &[
            0, 0, 0, 0, 0, 0, 0, 0, // preamble
            0, 1, 2, 3, 4, 5,      // destination MAC
            5, 4, 3, 2, 1, 0,       // source MAC
            0x08, 0x_00             // type (Iv4)
        ];

        assert_eq!(
            Ethernet2::new([0, 1, 2, 3, 4, 5], [5, 4, 3, 2, 1, 0], ProtocolType::Ipv4),
            Ethernet2::try_from(raw).unwrap());
    }

    #[test]
    fn ethernet2_from_raw_too_small() {
        let raw: &[u8] = &[
            0, 0, 0, 0, 0, 0, 0,    // preamble (1 byte too small)
            0, 1, 2, 3, 4, 5,       // destination MAC
            5, 4, 3, 2, 1, 0 ,      // source MAC
            0x08, 0x_00             // type (Iv4)
        ];

        if let Ok(_) = Ethernet2::try_from(raw) {
            panic!("too few bytes were provided, try_from should have failed");
        }
    }

    #[test]
    fn ethernet3_from_raw_empty_payload_ok() {
        let raw: &[u8] = &[
            0,  0,  0,  0,  0,  0,  0,  0,  // preamble
            0,  1,  2,  3,  4,  5,          // destination MAC
            5,  4,  3,  2,  1,  0,          // source MAC
            0,  0,                          // length
            0,  0,  0,  0,  0,  0,  0,  0,  // payload data
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,
            0,  0,  0,  1                      // frame check sequence
        ];

        assert_eq!(
            Ethernet3::new([0, 1, 2, 3, 4, 5], [5, 4, 3, 2, 1, 0], 0, 1),
            Ethernet3::try_from(raw).unwrap());
    }

    #[test]
    fn ethernet3_from_raw_half_full_ok() {
        let raw: &[u8] = &[
            0,  0,  0,  0,  0,  0,  0,  0,  // preamble
            0,  1,  2,  3,  4,  5,          // destination MAC
            5,  4,  3,  2,  1,  0,          // source MAC
            0,  24,                         // length
            0,  1,  2,  3,  4,  5,  6,  7,  // payload data
            8,  9,  10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23,
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,
            0,  0,  0,  1                   // frame check sequence
        ];

        assert_eq!(
            Ethernet3::new([0, 1, 2, 3, 4, 5], [5, 4, 3, 2, 1, 0], 24, 1),
            Ethernet3::try_from(raw).unwrap());
    }

    #[test]
    fn ethernet3_from_raw_exactly_full_ok() {
        let raw: &[u8] = &[
            0,  0,  0,  0,  0,  0,  0,  0,  // preamble
            0,  1,  2,  3,  4,  5,          // destination MAC
            5,  4,  3,  2,  1,  0,          // source MAC
            0,  46,                         // length
            0,  1,  2,  3,  4,  5,  6,  7,  // payload data
            8,  9,  10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
            32, 33, 34, 35, 36, 37, 38, 39,
            40, 41, 42, 43, 44, 45,
            0,  0,  0,  1                   // frame check sequence
        ];

        assert_eq!(
            Ethernet3::new([0, 1, 2, 3, 4, 5], [5, 4, 3, 2, 1, 0], 46, 1),
            Ethernet3::try_from(raw).unwrap());
    }

    #[test]
    fn ethernet3_from_raw_overfull_payload_ok() {
        let raw: &[u8] = &[
            0, 0, 0, 0, 0, 0, 0, 0,         // preamble
            0, 1, 2, 3, 4, 5,               // destination MAC
            5, 4, 3, 2, 1, 0 ,              // source MAC
            0, 48,                          // length
            0,  1,  2,  3,  4,  5,  6,  7,  // payload data
            8,  9,  10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
            32, 33, 34, 35, 36, 37, 38, 39,
            40, 41, 42, 43, 44, 45, 46, 47,
            0,  0,  0,  1                   // frame check sequence
        ];

        assert_eq!(
            Ethernet3::new([0, 1, 2, 3, 4, 5], [5, 4, 3, 2, 1, 0], 48, 1),
            Ethernet3::try_from(raw).unwrap());
    }

    #[test]
    fn ethernet_from_raw_too_small() {
        let raw: &[u8] = &[
            0,  0,  0,  0,  0,  0,  0,      // preamble (1 bytes too small)
            0,  1,  2,  3,  4,  5,          // destination MAC
            5,  4,  3,  2,  1,  0,          // source MAC
            0,  0,                          // length
            0,  0,  0,  0,  0,  0,  0,  0,  // payload data
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,
            0,  0,  0,  1                      // frame check sequence
        ];

        if let Ok(n) = Ethernet3::try_from(raw) {
            panic!("too few bytes were provided, try_from should have failed");
        }

    }
}