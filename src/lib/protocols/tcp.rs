use std::collections::{HashMap, HashSet};
use std::convert::TryFrom;

use num_traits::FromPrimitive;

use crate::error::NbugError;
use crate::protocols::{ProtocolNumber, ProtocolPacket};

pub static CONTROL_BITS_KEY: &str = "CONTROL_BITS";

static SEQUENCE_NUMBER: &str = "SEQUENCE_NUMBER";

static ACKNOWLEDGEMENT_NUMBER: &str = "ACKNOWLEDGEMENT_NUMBER";

#[derive(Clone, Debug, FromPrimitive, PartialEq)]
pub enum TcpOptionKind {
    End            = 0,
    NoOp           = 1,
    MaxSegmentSize = 2,
    WindowScale    = 3,
    SelectiveAck   = 4,
    Timestamp      = 8,
}

#[derive(Clone, Debug, PartialEq)]
pub struct TcpOption {
    kind:       TcpOptionKind,
    pub length: Option<u8>,
}

impl TryFrom<&[u8]> for TcpOption {
    type Error = NbugError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let kind = match FromPrimitive::from_u8(value[0]) {
            Some(kind) => kind,
            None =>
                return Err(NbugError::Packet(format!(
                    "Unknown tcp option kind value '{}'",
                    value[0]
                ))),
        };

        let length = match kind {
            TcpOptionKind::End | TcpOptionKind::NoOp => None,
            _ =>
                if value.len() == 1 {
                    return Err(NbugError::Packet(
                        "Too few bytes given for tcp option, expected a length".to_string(),
                    ));
                } else {
                    Some(value[1])
                },
        };

        Ok(TcpOption { kind, length })
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum TcpControlBits {
    Urg = 0b00_100000,
    Ack = 0b00_010000,
    Psh = 0b00_001000,
    Rst = 0b00_000100,
    Syn = 0b00_000010,
    Fin = 0b00_000001,
}

impl TcpControlBits {
    /// Build a [HashSet] of [TcpControlBits] from a single u8 based on which
    /// bits are set. Note that this method will not only look at the 6 least
    /// significant bits, so if either or both of the 2 most significant bits
    /// are set, the returned set will be empty.
    pub fn find_control_bits(bits: u8) -> HashSet<TcpControlBits> {
        let mut set = HashSet::<TcpControlBits>::with_capacity(6);

        if bits & TcpControlBits::Urg as u8 == TcpControlBits::Urg as u8 {
            set.insert(TcpControlBits::Urg);
        }

        if bits & TcpControlBits::Ack as u8 == TcpControlBits::Ack as u8 {
            set.insert(TcpControlBits::Ack);
        }

        if bits & TcpControlBits::Psh as u8 == TcpControlBits::Psh as u8 {
            set.insert(TcpControlBits::Psh);
        }

        if bits & TcpControlBits::Rst as u8 == TcpControlBits::Rst as u8 {
            set.insert(TcpControlBits::Rst);
        }

        if bits & TcpControlBits::Syn as u8 == TcpControlBits::Syn as u8 {
            set.insert(TcpControlBits::Syn);
        }

        if bits & TcpControlBits::Fin as u8 == TcpControlBits::Fin as u8 {
            set.insert(TcpControlBits::Fin);
        }

        set
    }

    pub fn is_syn(control_bits: &HashSet<TcpControlBits>) -> bool {
        control_bits.contains(&TcpControlBits::Syn) && control_bits.len() == 1
    }

    pub fn is_ack(control_bits: &HashSet<TcpControlBits>) -> bool {
        control_bits.contains(&TcpControlBits::Ack) && control_bits.len() == 1
    }

    pub fn is_syn_ack(control_bits: &HashSet<TcpControlBits>) -> bool {
        control_bits.contains(&TcpControlBits::Syn)
            && control_bits.contains(&TcpControlBits::Ack)
            && control_bits.len() == 2
    }

    pub fn is_fin(control_bits: &HashSet<TcpControlBits>) -> bool {
        control_bits.contains(&TcpControlBits::Fin) && control_bits.len() == 1
    }
}

/// The TCP Packet as specified in [RFC 793 3.1](https://tools.ietf.org/html/rfc793#section-3.1).
#[derive(Clone, Debug, PartialEq)]
pub struct TcpPacket {
    pub source_port: u16,

    pub destination_port: u16,

    pub sequence_number: u32,

    pub acknowledgement_number: u32,

    pub offset: u8,

    pub control_bits: u8,

    pub window: u16,

    pub checksum: u16,

    pub urgent_pointer: u16,

    pub options: Option<Vec<TcpOption>>,
}

impl TcpPacket {
    const MIN_BYTES: usize = 20;
}

impl TryFrom<&[u8]> for TcpPacket {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < TcpPacket::MIN_BYTES {
            return Err(NbugError::Packet(String::from(format!(
                "Too few bytes, expected at least {}",
                TcpPacket::MIN_BYTES
            ))));
        }

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

        let offset = (data[12] >> 4) * 4;
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

        let options: Option<Vec<TcpOption>> = if offset as usize == TcpPacket::MIN_BYTES {
            None
        } else {
            let mut options = vec![];
            let mut option_start = TcpPacket::MIN_BYTES;

            while option_start < offset as usize {
                let option = match TcpOption::try_from(&data[option_start..]) {
                    Ok(option) => option,
                    Err(err) => return Err(err),
                };

                option_start += match option.length {
                    Some(n) => n as usize,
                    None => 1,
                };

                options.push(option);
            }

            Some(options)
        };

        Ok(TcpPacket {
            source_port,
            destination_port,
            sequence_number,
            acknowledgement_number,
            offset,
            control_bits,
            window,
            checksum,
            urgent_pointer,
            options,
        })
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use crate::protocols::tcp::{TcpOption, TcpOptionKind, TcpPacket};

    const SAMPLE_TCP_SYN_DATA: &[u8] = &[
        0xcc, 0xfe, // source port
        0x1f, 0x92, // destination port
        0x0a, 0x04, 0x08, 0x62, // sequence number
        0x00, 0x00, 0x00, 0x00, // acknowledgement number
        0x50, 0x02, // offset (header length) && control bits
        0xff, 0xd7, // window
        0xfe, 0x30, // checksum
        0x00, 0x00, // urgent pointer
    ];

    #[test]
    fn test_tcp_basic_ok() {
        let actual = TcpPacket::try_from(SAMPLE_TCP_SYN_DATA).unwrap();
        let expected = TcpPacket {
            source_port:            0xcc_fe,
            destination_port:       0x1f_92,
            sequence_number:        0x0a_04_08_62,
            acknowledgement_number: 0x00_00_00_00,
            offset:                 20,
            control_bits:           0x002,
            window:                 0xff_d7,
            checksum:               0xfe_30,
            urgent_pointer:         0x_00,
            options:                None,
        };

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_tcp_with_options() {
        let raw: &[u8] = &[
            0xcc, 0xfe, // source port
            0x1f, 0x92, // destination port
            0x0a, 0x04, 0x08, 0x62, // sequence number
            0x00, 0x00, 0x00, 0x00, // acknowledgement number
            0xa0, 0x02, // offset (header length) && control bits
            0xff, 0xd7, // window
            0xfe, 0x30, // checksum
            0x00, 0x00, // urgent pointer
            // options
            0x02, 0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a, 0x27, 0xb8, 0xac, 0x99, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03,
            0x03, 0x0,
        ];

        let actual = TcpPacket::try_from(raw).unwrap();
        let expected = TcpPacket {
            source_port:            0xcc_fe,
            destination_port:       0x1f_92,
            sequence_number:        0x0a_04_08_62,
            acknowledgement_number: 0x00_00_00_00,
            offset:                 40,
            control_bits:           0x002,
            window:                 0xff_d7,
            checksum:               0xfe_30,
            urgent_pointer:         0x_00,
            options:                Some(vec![
                TcpOption {
                    kind:   TcpOptionKind::MaxSegmentSize,
                    length: Some(4),
                },
                TcpOption {
                    kind:   TcpOptionKind::SelectiveAck,
                    length: Some(2),
                },
                TcpOption {
                    kind:   TcpOptionKind::Timestamp,
                    length: Some(10),
                },
                TcpOption {
                    kind:   TcpOptionKind::NoOp,
                    length: None,
                },
                TcpOption {
                    kind:   TcpOptionKind::WindowScale,
                    length: Some(3),
                },
            ]),
        };

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_tcp_too_short() {
        if let Ok(_) = TcpPacket::try_from(&SAMPLE_TCP_SYN_DATA[1..]) {
            panic!("too few bytes were provided, try_from should have failed");
        }
    }
}
