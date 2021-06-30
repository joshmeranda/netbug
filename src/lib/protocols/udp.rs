use std::collections::HashMap;
use std::convert::TryFrom;

use crate::error::NbugError;
use crate::protocols::{ProtocolNumber, ProtocolPacket, DST_PORT_KEY, SRC_PORT_KEY};

/// The UDP Packet a s specified in [RFC 768](https://tools.ietf.org/html/rfc768).
#[derive(Clone, Debug, PartialEq)]
pub struct UdpPacket {
    pub source_port: u16,

    pub destination_port: u16,

    pub length: u16,

    pub checksum: u16,
}

impl UdpPacket {
    const BYTES: usize = 8;
}

impl TryFrom<&[u8]> for UdpPacket {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < UdpPacket::BYTES {
            return Err(NbugError::Packet(String::from(format!(
                "Too few bytes, expected at least {}",
                UdpPacket::BYTES
            ))));
        }

        let mut source_bytes = [0u8; 2];
        source_bytes.copy_from_slice(&data[0..2]);
        let source_port = u16::from_be_bytes(source_bytes);

        let mut destination_bytes = [0u8; 2];
        destination_bytes.copy_from_slice(&data[2..4]);
        let destination_port = u16::from_be_bytes(destination_bytes);

        let mut length_bytes = [0u8; 2];
        length_bytes.copy_from_slice(&data[4..6]);
        let length = u16::from_be_bytes(length_bytes);

        let mut checksum_bytes = [0u8; 2];
        checksum_bytes.copy_from_slice(&data[6..8]);
        let checksum = u16::from_be_bytes(checksum_bytes);

        Ok(UdpPacket {
            source_port,
            destination_port,
            length,
            checksum,
        })
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use crate::protocols::udp::UdpPacket;

    const SAMPLE_UDP_DATA: &[u8] = &[0xe9, 0x5d, 0x1f, 0x91, 0x00, 0xab, 0xfe, 0xbe];

    #[test]
    fn test_udp_ok() {
        let actual = UdpPacket::try_from(SAMPLE_UDP_DATA).unwrap();
        let expected = UdpPacket {
            source_port:      0xe9_5d,
            destination_port: 0x1f_91,
            length:           0x00_ab,
            checksum:         0xfe_be,
        };

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_udp_too_short() {
        if let Ok(_) = UdpPacket::try_from(&SAMPLE_UDP_DATA[1..]) {
            panic!("too few bytes were provided, try_from should have failed");
        }
    }
}
