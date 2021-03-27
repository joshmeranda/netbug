use std::convert::TryFrom;

use crate::error::NbugError;
use crate::protocols::{ProtocolNumber, ProtocolPacketHeader};

enum TcpControlBits {
    Urg = 0b00_100000,
    Ack = 0b00_010000,
    Psh = 0b00_001000,
    Rst = 0b00_000100,
    Syn = 0b00_000010,
    Fin = 0b00_000001,
}

/// The TCP Packet as specified in [RFC 793 3.1](https://tools.ietf.org/html/rfc793#section-3.1).
struct Tcp {
    source_port: u16,

    destination_port: u16,

    sequence_number: u32,

    acknowledgement_number: u32,

    offset: u8,

    control_bits: u8,

    window: u16,

    checksum: u16,

    urgent_pointer: u16,
}

impl TryFrom<&[u8]> for Tcp {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        unimplemented!();

        let mut source_bytes = [0u8; 2];
        source_bytes.copy_from_slice(&data[0..2]);
        let source_port = u16::from_be_bytes(source_bytes);

        let mut destination_bytes = [0u8; 2];
        destination_bytes.copy_from_slice(&data[2..4]);
        let destination_port = u16::from_be_bytes(destination_bytes);

        let mut sequence_bytes = [0u8; 4];
        sequence_bytes.copy_from_slice(&data[4..8]);
        let sequence_number = u32::from_be_bytes(sequence_bytes);

        let mut acknowledge_bytes = [0u8; 4];
        acknowledge_bytes.copy_from_slice(&data[8..12]);
        let acknowledgement_number = u32::from_be_bytes(acknowledge_bytes);

        let offset = data[12] >> 4;
        let control_bits = data[13] & 0b0011_1111;

        let mut window_bytes = [0u8; 2];
        window_bytes.copy_from_slice(&data[14..16]);
        let window = u16::from_be_bytes(window_bytes);

        let mut checksum_bytes = [0u8; 2];
        checksum_bytes.copy_from_slice(&data[16..18]);
        let checksum = u16::from_be_bytes(checksum_bytes);

        let mut urgent_bytes = [0u8; 2];
        urgent_bytes.copy_from_slice(&data[18..20]);
        let urgent_pointer = u16::from_be_bytes(urgent_bytes);

        Ok(Tcp {
            source_port,
            destination_port,
            sequence_number,
            acknowledgement_number,
            offset,
            control_bits,
            window,
            checksum,
            urgent_pointer,
        })
    }
}

impl ProtocolPacketHeader for Tcp {
    fn header_length(&self) -> usize { 24 }

    fn protocol_type(&self) -> ProtocolNumber { ProtocolNumber::Tcp }
}
