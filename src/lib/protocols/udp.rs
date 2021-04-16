use std::collections::HashMap;
use std::convert::TryFrom;

use crate::error::NbugError;
use crate::protocols::{ProtocolNumber, ProtocolPacketHeader, DST_PORT_KEY, SRC_PORT_KEY};

/// The UDP Packet a s specified in [RFC 768](https://tools.ietf.org/html/rfc768).
pub struct UdpPacket {
    source_port: u16,

    destination_port: u16,

    length: u16,

    checksum: u16,
}

impl TryFrom<&[u8]> for UdpPacket {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut source_bytes = [0u8; 2];
        source_bytes.copy_from_slice(&data[0..2]);
        let source_port = u16::from_be_bytes(source_bytes);

        let mut destination_bytes = [0u8; 2];
        destination_bytes.copy_from_slice(&data[0..2]);
        let destination_port = u16::from_be_bytes(destination_bytes);

        let mut length_bytes = [0u8; 2];
        length_bytes.copy_from_slice(&data[0..2]);
        let length = u16::from_be_bytes(length_bytes);

        let mut checksum_bytes = [0u8; 2];
        checksum_bytes.copy_from_slice(&data[0..2]);
        let checksum = u16::from_be_bytes(checksum_bytes);

        Ok(UdpPacket {
            source_port,
            destination_port,
            length,
            checksum,
        })
    }
}

impl ProtocolPacketHeader for UdpPacket {
    fn header_length(&self) -> usize { 8 }

    fn protocol_type(&self) -> ProtocolNumber { ProtocolNumber::Udp }

    fn header_data(&self) -> Option<HashMap<&str, u64>> {
        let mut data = HashMap::<&str, u64>::new();

        data.insert(SRC_PORT_KEY, self.source_port as u64);
        data.insert(DST_PORT_KEY, self.destination_port as u64);

        Some(data)
    }
}
