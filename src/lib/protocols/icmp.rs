use std::convert::TryFrom;

use crate::error::NbugError;
use crate::protocols::icmp::icmpv4::Icmpv4Packet;
use crate::protocols::icmp::icmpv6::Icmpv6Packet;

pub static ICMP_KIND_KEY: &str = "IcmpKind";

pub static MIN_ICMP_HEADER_LEN: usize = 8;

/// Simple wrapper around icmp types. Since neither icmp version 4 or 6 provide
/// a method for asserting the version beyond the type used in the internet
/// header, they must be parsed separately before being wrapped into this enum.
///
/// # Examples
/// ```
/// use netbug::protocols::icmp::icmpv6::Icmpv6Packet;
/// use netbug::protocols::icmp::icmpv4::Icmpv4Packet;
/// use netbug::protocols::icmp::IcmpPacket;
/// use std::convert::TryFrom;
///
/// let data4: &[u8] = &[0x08, 0x00, 0x72, 0x0e, 0x00, 0x0e, 0x00, 0x01, 0x1b, 0x77, 0x47, 0x60, 0x00, 0x00, 0x00, 0x00];
/// let data6: &[u8] = &[0x80, 0x00, 0x00, 0xa5, 0x00, 0x0d, 0x00, 0x01];
///
/// let icmp4 = IcmpPacket::V4(Icmpv4Packet::try_from(data4).unwrap());
/// let icmp6 = IcmpPacket::V6(Icmpv6Packet::try_from(data6).unwrap());
/// ```
#[derive(Clone, Debug, PartialEq)]
pub enum IcmpPacket {
    V4(Icmpv4Packet),
    V6(Icmpv6Packet),
}

/// Simple wrapper around an icmp echo and reply packet as defined in [RFC 4443 4.1](https://tools.ietf.org/html/rfc4443#section-4.1)
/// and similarly in [RFC 794 pg 14](https://tools.ietf.org/html/rfc792#page-14)
#[derive(Clone, Debug, PartialEq)]
pub struct IcmpCommon {
    pub kind:       u8,
    pub code:       u8,
    pub checksum:   u16,
    pub identifier: u16,
    pub sequence:   u16,
}

impl TryFrom<&[u8]> for IcmpCommon {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < 6 {
            return Err(NbugError::Packet(format!("Too few bytes, expected at least {}", 6)));
        }

        let icmp_type = data[0];
        let code = data[1];

        let mut checksum_bytes = [0u8; 2];
        checksum_bytes.copy_from_slice(&data[2..4]);
        let checksum = u16::from_be_bytes(checksum_bytes);

        let mut identifier_bytes = [0u8; 2];
        identifier_bytes.copy_from_slice(&data[4..6]);
        let identifier = u16::from_be_bytes(identifier_bytes);

        let mut sequence_bytes = [0u8; 2];
        sequence_bytes.copy_from_slice(&data[6..8]);
        let sequence = u16::from_be_bytes(sequence_bytes);

        Ok(IcmpCommon {
            kind: icmp_type,
            code,
            checksum,
            identifier,
            sequence,
        })
    }
}

pub mod icmpv4 {
    use std::cmp::PartialEq;
    use std::convert::TryFrom;
    use std::net::Ipv4Addr;

    use num_traits::FromPrimitive;

    use crate::error::NbugError;
    use crate::protocols::icmp::{IcmpCommon, MIN_ICMP_HEADER_LEN};
    use crate::protocols::ip::Ipv4Packet;

    /// Maps variants to icmp message types as defined in [RFC 792 Summary of Message Types](https://tools.ietf.org/html/rfc792#page-20)
    #[derive(Clone, Debug, FromPrimitive, PartialEq)]
    pub enum Icmpv4MessageKind {
        EchoReply          = 0,
        DestinationUnreachable = 3,
        SourceQuench       = 4,
        Redirect           = 5,
        EchoRequest        = 8,
        TimeExceeded       = 11,
        ParameterProblem   = 12,
        TimestampRequest   = 13,
        TimestampReply     = 14,
        InformationRequest = 15,
        InformationReply   = 16,
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct IcmpTimestamp {
        pub common:             IcmpCommon,
        pub original_timestamp: u32,
        pub receive_timestamp:  u32,
        pub transmit_timestamp: u32,
    }

    impl TryFrom<&[u8]> for IcmpTimestamp {
        type Error = NbugError;

        fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
            if data.len() < 18 {
                return Err(NbugError::Packet(format!("Too few bytes, expected at least {}", 18)));
            }

            let common = IcmpCommon::try_from(data)?;

            let mut original_bytes = [0u8; 4];
            original_bytes.copy_from_slice(&data[6..10]);
            let original_timestamp = u32::from_be_bytes(original_bytes);

            let mut receive_bytes = [0u8; 4];
            receive_bytes.copy_from_slice(&data[10..14]);
            let receive_timestamp = u32::from_be_bytes(receive_bytes);

            let mut transmit_bytes = [0u8; 4];
            transmit_bytes.copy_from_slice(&data[14..18]);
            let transmit_timestamp = u32::from_be_bytes(transmit_bytes);

            Ok(IcmpTimestamp {
                common,
                original_timestamp,
                receive_timestamp,
                transmit_timestamp,
            })
        }
    }

    #[derive(Clone, Debug, PartialEq)]
    pub struct IcmpErrorPacket {
        pub checksum:        u16,
        pub internet_header: Ipv4Packet,
    }

    impl TryFrom<&[u8]> for IcmpErrorPacket {
        type Error = NbugError;

        fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
            let mut checksum_bytes = [0u8; 2];
            checksum_bytes.copy_from_slice(&data[2..4]);
            let checksum = u16::from_be_bytes(checksum_bytes);

            let internet_header = Ipv4Packet::try_from(&data[8..])?;

            Ok(IcmpErrorPacket {
                checksum,
                internet_header,
            })
        }
    }

    /// Defines the variants of icmp v4 packets as defined in [RFC 792](https://tools.ietf.org/html/rfc792)
    #[derive(Clone, Debug, PartialEq)]
    pub enum Icmpv4Packet {
        /// Described in [RFC 792 Pg 14](https://tools.ietf.org/html/rfc792#page-14)
        EchoReply(IcmpCommon),

        /// Described in [RFC 792 Pg 4](https://tools.ietf.org/html/rfc792#page-4)
        DestinationUnreachable(IcmpErrorPacket),

        /// Described in [RFC 792 Pg 10](https://tools.ietf.org/html/rfc792#page-10)
        SourceQuench(IcmpErrorPacket),

        /// Described in [RFC 792 Pg 12](https://tools.ietf.org/html/rfc792#page-12)
        Redirect {
            error:           IcmpErrorPacket,
            gateway_address: Ipv4Addr,
        },

        /// Described in [RFC 792 Pg 14](https://tools.ietf.org/html/rfc792#page-14)
        EchoRequest(IcmpCommon),

        /// Described in [RFC 792 Pg 6](https://tools.ietf.org/html/rfc792#page-6)
        TimeExceeded(IcmpErrorPacket),

        /// Described in [RFC 792 Pg 8](https://tools.ietf.org/html/rfc792#page-8)
        ParameterProblem { error: IcmpErrorPacket, pointer: u8 },

        /// Described in [RFC 792 Pg 16](https://tools.ietf.org/html/rfc792#page-16)
        TimestampRequest(IcmpTimestamp),

        /// Described in [RFC 792 Pg 16](https://tools.ietf.org/html/rfc792#page-16)
        TimestampReply(IcmpTimestamp),

        /// Described in [RFC 792 Pg 16](https://tools.ietf.org/html/rfc792#page-18)
        InformationRequest(IcmpCommon),

        /// Described in [RFC 792 Pg 16](https://tools.ietf.org/html/rfc792#page-18)
        InformationReply(IcmpCommon),
    }

    impl Icmpv4Packet {
        pub fn message_kind(&self) -> Icmpv4MessageKind {
            match self {
                Icmpv4Packet::EchoReply(_) => Icmpv4MessageKind::EchoReply,
                Icmpv4Packet::DestinationUnreachable(_) => Icmpv4MessageKind::DestinationUnreachable,
                Icmpv4Packet::SourceQuench(_) => Icmpv4MessageKind::SourceQuench,
                Icmpv4Packet::Redirect { .. } => Icmpv4MessageKind::Redirect,
                Icmpv4Packet::EchoRequest(_) => Icmpv4MessageKind::EchoRequest,
                Icmpv4Packet::TimeExceeded(_) => Icmpv4MessageKind::TimeExceeded,
                Icmpv4Packet::ParameterProblem { .. } => Icmpv4MessageKind::ParameterProblem,
                Icmpv4Packet::TimestampRequest(_) => Icmpv4MessageKind::TimestampRequest,
                Icmpv4Packet::TimestampReply(_) => Icmpv4MessageKind::TimestampReply,
                Icmpv4Packet::InformationRequest(_) => Icmpv4MessageKind::InformationRequest,
                Icmpv4Packet::InformationReply(_) => Icmpv4MessageKind::InformationReply,
            }
        }
    }

    impl TryFrom<&[u8]> for Icmpv4Packet {
        type Error = NbugError;

        fn try_from(data: &[u8]) -> Result<Icmpv4Packet, Self::Error> {
            if data.len() < MIN_ICMP_HEADER_LEN {
                return Err(NbugError::Packet(format!(
                    "Too few bytes, expected at least: {}",
                    MIN_ICMP_HEADER_LEN
                )));
            }

            let kind =
                FromPrimitive::from_u8(data[0]).expect(&*format!("Invalid icmp message type value '{}'", data[0]));

            match kind {
                Icmpv4MessageKind::EchoReply => Ok(Icmpv4Packet::EchoReply(IcmpCommon::try_from(data)?)),
                Icmpv4MessageKind::DestinationUnreachable =>
                    Ok(Icmpv4Packet::DestinationUnreachable(IcmpErrorPacket::try_from(data)?)),
                Icmpv4MessageKind::SourceQuench => Ok(Icmpv4Packet::SourceQuench(IcmpErrorPacket::try_from(data)?)),
                Icmpv4MessageKind::Redirect => {
                    let error = IcmpErrorPacket::try_from(data)?;

                    let mut gateway_bytes = [0u8; 4];
                    gateway_bytes.copy_from_slice(&data[4..8]);
                    let gateway_address = Ipv4Addr::from(gateway_bytes);

                    Ok(Icmpv4Packet::Redirect { error, gateway_address })
                },
                Icmpv4MessageKind::EchoRequest => Ok(Icmpv4Packet::EchoRequest(IcmpCommon::try_from(data)?)),
                Icmpv4MessageKind::TimeExceeded => Ok(Icmpv4Packet::TimeExceeded(IcmpErrorPacket::try_from(data)?)),
                Icmpv4MessageKind::ParameterProblem => {
                    let error = IcmpErrorPacket::try_from(data)?;
                    let pointer = data[4];

                    Ok(Icmpv4Packet::ParameterProblem { error, pointer })
                },
                Icmpv4MessageKind::TimestampRequest =>
                    Ok(Icmpv4Packet::TimestampRequest(IcmpTimestamp::try_from(data)?)),
                Icmpv4MessageKind::TimestampReply => Ok(Icmpv4Packet::TimestampReply(IcmpTimestamp::try_from(data)?)),
                Icmpv4MessageKind::InformationRequest =>
                    Ok(Icmpv4Packet::InformationRequest(IcmpCommon::try_from(data)?)),
                Icmpv4MessageKind::InformationReply => Ok(Icmpv4Packet::InformationReply(IcmpCommon::try_from(data)?)),
            }
        }
    }
}

pub mod icmpv6 {
    use std::convert::TryFrom;

    use num_traits::FromPrimitive;

    use crate::error::NbugError;
    use crate::protocols::icmp::{IcmpCommon, MIN_ICMP_HEADER_LEN};

    /// Map variants to icmp v6 message types as defined in [RFC 4443 2.1](https://tools.ietf.org/html/rfc4443#section-2.1).
    #[derive(Clone, Debug, FromPrimitive, PartialEq)]
    pub enum Icmpv6MessageKind {
        DestinationUnreachable = 1,
        PacketTooBig     = 2,
        TimeExceeded     = 3,
        ParameterProblem = 4,
        PrivateExperimentationError1 = 100,
        PrivateExperimentationError2 = 101,
        ReservedForErrorExpansion = 127,

        EchoRequest      = 128,
        EchoReply        = 129,
        PrivateExperimentationInformational1 = 200,
        PrivateExperimentationInformational2 = 201,
        ReservedForInformationalExpansion = 255,
    }

    /// As defined in [RFC 4443 Section 3.1](https://tools.ietf.org/html/rfc4443#section-3.1)
    #[derive(Clone, Debug, FromPrimitive, PartialEq)]
    pub enum DestinationUnreachableCode {
        NoRoute             = 0,
        Prohibited          = 1,
        BeyondScope         = 2,
        AddressUnreachable  = 3,
        PortUnreachable     = 4,
        FailedTrafficPolicy = 5,
        RejectedRoute       = 6,
    }

    /// As defined in [RFC 443 Section 3.3](https://tools.ietf.org/html/rfc4443#section-3.3)
    #[derive(Clone, Debug, FromPrimitive, PartialEq)]
    pub enum TimeExceededCode {
        HopLimitExceeded = 0,
        FragmentReassemblyExceeded = 1,
    }

    /// As defined in [RFC 443 Section 3.4](https://tools.ietf.org/html/rfc4443#section-3.4)
    #[derive(Clone, Debug, FromPrimitive, PartialEq)]
    pub enum ParameterProblemCode {
        ErroneousHeader    = 0,
        UnrecognizedNextHeader = 1,
        UnrecognizedOption = 2,
    }

    /// Defines icmp message types as defined in [RFC 4443](https://tools.ietf.org/html/rfc792)
    ///
    /// todo: figure out the invoking packet
    /// todo: support more message types
    #[derive(Clone, Debug, PartialEq)]
    pub enum Icmpv6Packet {
        EchoRequest(IcmpCommon),

        EchoReply(IcmpCommon),
    }

    impl Icmpv6Packet {
        pub fn message_kind(&self) -> Icmpv6MessageKind {
            match self {
                Icmpv6Packet::EchoRequest(_) => Icmpv6MessageKind::EchoRequest,
                Icmpv6Packet::EchoReply(_) => Icmpv6MessageKind::EchoReply,
            }
        }
    }

    impl TryFrom<&[u8]> for Icmpv6Packet {
        type Error = NbugError;

        fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
            if data.len() < MIN_ICMP_HEADER_LEN {
                return Err(NbugError::Packet(format!(
                    "Too few bytes, expected at least: {}",
                    MIN_ICMP_HEADER_LEN
                )));
            }

            let kind =
                FromPrimitive::from_u8(data[0]).expect(&*format!("Invalid icmp message type value '{}'", data[0]));

            match kind {
                Icmpv6MessageKind::EchoRequest => Ok(Icmpv6Packet::EchoRequest(IcmpCommon::try_from(data)?)),
                Icmpv6MessageKind::EchoReply => Ok(Icmpv6Packet::EchoReply(IcmpCommon::try_from(data)?)),
                _ => Err(NbugError::Packet(format!("unhandled message type '{}'", data[0]))),
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryFrom;

    use crate::protocols::icmp::icmpv4::Icmpv4Packet;
    use crate::protocols::icmp::icmpv6::Icmpv6Packet;
    use crate::protocols::icmp::IcmpCommon;

    const SAMPLE_ICMP_V4_DATA: &[u8] = &[
        0x00, // type (echo reply)
        0x00, // code
        0x0c, 0x7b, // checksum
        0x00, 0x02, // identifier
        0x00, 0x01, // sequence number
    ];

    const SAMPLE_ICMP_V6_DATA: &[u8] = &[
        0x80, // type (echo request)
        0x00, // code
        0x7a, 0x78, // checksum
        0x00, 0x2c, // identifier
        0x00, 0x01, // sequence number
    ];

    #[test]
    fn test_icmp_v4_ok() {
        let actual = Icmpv4Packet::try_from(SAMPLE_ICMP_V4_DATA).unwrap();
        let expected = Icmpv4Packet::EchoReply(IcmpCommon {
            kind:       0x0,
            code:       0x0,
            checksum:   0x0c7b,
            identifier: 0x02,
            sequence:   0x01,
        });

        assert_eq!(expected, actual);
    }

    #[test]
    fn test_icmp_v4_too_small() {
        if let Ok(_) = Icmpv4Packet::try_from(&SAMPLE_ICMP_V4_DATA[1..]) {
            panic!("too few bytes were provided, try_from should have failed");
        }
    }

    #[test]
    fn test_icmp_v6_ok() {
        let actual = Icmpv6Packet::try_from(SAMPLE_ICMP_V6_DATA).unwrap();
        let expected = Icmpv6Packet::EchoRequest(IcmpCommon {
            kind:       0x80,
            code:       0x00,
            checksum:   0x7a78,
            identifier: 0x2c,
            sequence:   0x01,
        });

        assert_eq!(expected, actual)
    }

    #[test]
    fn test_icmp_v6_too_small() {
        if let Ok(_) = Icmpv6Packet::try_from(&SAMPLE_ICMP_V6_DATA[1..]) {
            panic!("too few bytes were provided, try_from should have failed");
        }
    }
}
