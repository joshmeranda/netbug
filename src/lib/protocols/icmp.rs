use std::convert::TryFrom;

use crate::error::NbugError;
use crate::protocols::icmp::icmpv4::Icmpv4Packet;
use crate::protocols::icmp::icmpv6::Icmpv6Packet;
use crate::protocols::{ProtocolNumber, ProtocolPacketHeader};

pub static ICMP_KIND_KEY: &str = "IcmpKind";

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
pub enum IcmpPacket {
    V4(Icmpv4Packet),
    V6(Icmpv6Packet),
}

impl ProtocolPacketHeader for IcmpPacket {
    fn header_length(&self) -> usize {
        match self {
            IcmpPacket::V4(packet) => packet.header_length(),
            IcmpPacket::V6(packet) => packet.header_length(),
        }
    }

    fn protocol_type(&self) -> ProtocolNumber {
        match self {
            IcmpPacket::V4(packet) => packet.protocol_type(),
            IcmpPacket::V6(packet) => packet.protocol_type(),
        }
    }
}

/// Simple wrapper around an icmp echo and reply packet as defined in [RFC 4443 4.1](https://tools.ietf.org/html/rfc4443#section-4.1)
/// and similarly in [RFC 794 pg 14](https://tools.ietf.org/html/rfc792#page-14)
pub struct IcmpCommon {
    checksum:   u16,
    identifier: u16,
    sequence:   u16,
}

impl TryFrom<&[u8]> for IcmpCommon {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        if data.len() < 6 {
            return Err(NbugError::Packet(String::from(format!(
                "Too few bytes, expected at least {}",
                6
            ))));
        }

        let mut checksum_bytes = [0u8; 2];
        checksum_bytes.copy_from_slice(&data[0..2]);
        let checksum = u16::from_be_bytes(checksum_bytes);

        let mut identifier_bytes = [0u8; 2];
        identifier_bytes.copy_from_slice(&data[0..2]);
        let identifier = u16::from_be_bytes(identifier_bytes);

        let mut sequence_bytes = [0u8; 2];
        sequence_bytes.copy_from_slice(&data[0..2]);
        let sequence = u16::from_be_bytes(sequence_bytes);

        Ok(IcmpCommon {
            checksum,
            identifier,
            sequence,
        })
    }
}

pub mod icmpv4 {
    use std::collections::HashMap;
    use std::convert::TryFrom;
    use std::net::Ipv4Addr;

    use num_traits::FromPrimitive;

    use crate::error::NbugError;
    use crate::protocols::icmp::{IcmpCommon, ICMP_KIND_KEY};
    use crate::protocols::ip::Ipv4Packet;
    use crate::protocols::{ProtocolNumber, ProtocolPacketHeader};

    /// Maps variants to icmp message types as defined in [RFC 792 Summary of Message Types](https://tools.ietf.org/html/rfc792#page-20)
    #[derive(FromPrimitive)]
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

    pub struct IcmpTimestamp {
        common:             IcmpCommon,
        original_timestamp: u32,
        receive_timestamp:  u32,
        transmit_timestamp: u32,
    }

    impl TryFrom<&[u8]> for IcmpTimestamp {
        type Error = NbugError;

        fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
            if data.len() < 18 {
                return Err(NbugError::Packet(String::from(format!(
                    "Too few bytes, expected at least {}",
                    18
                ))));
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

    pub struct IcmpErrorPacket {
        checksum:        u16,
        internet_header: Ipv4Packet,
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

    impl ProtocolPacketHeader for Icmpv4Packet {
        fn header_length(&self) -> usize {
            match self {
                Icmpv4Packet::EchoReply(_)
                | Icmpv4Packet::EchoRequest(_)
                | Icmpv4Packet::InformationRequest(_)
                | Icmpv4Packet::InformationReply(_) => 6,

                Icmpv4Packet::DestinationUnreachable(error)
                | Icmpv4Packet::SourceQuench(error)
                | Icmpv4Packet::TimeExceeded(error) => 2 + error.internet_header.header_length(),

                Icmpv4Packet::TimestampRequest(_) | Icmpv4Packet::TimestampReply(_) => 6 + 12,

                Icmpv4Packet::ParameterProblem { error, .. } => 2 + error.internet_header.header_length() + 1,

                Icmpv4Packet::Redirect { error, .. } => 2 + error.internet_header.header_length() + 4,
            }
        }

        fn protocol_type(&self) -> ProtocolNumber { ProtocolNumber::Icmp }

        fn header_data(&self) -> Option<HashMap<&str, u64>> {
            let mut data = HashMap::<&str, u64>::new();

            data.insert(ICMP_KIND_KEY, self.message_kind() as u64);

            Some(data)
        }
    }
}

pub mod icmpv6 {
    use std::collections::HashMap;
    use std::convert::TryFrom;

    use num_traits::FromPrimitive;

    use crate::error::NbugError;
    use crate::protocols::icmp::{IcmpCommon, ICMP_KIND_KEY};
    use crate::protocols::{ProtocolNumber, ProtocolPacketHeader};

    /// Map variants to icmp v6 message types as defined in [RFC 4443 2.1](https://tools.ietf.org/html/rfc4443#section-2.1).
    #[derive(FromPrimitive)]
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
    #[derive(FromPrimitive)]
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
    #[derive(FromPrimitive)]
    pub enum TimeExceededCode {
        HopLimitExceeded = 0,
        FragmentReassemblyExceeded = 1,
    }

    /// As defined in [RFC 443 Section 3.4](https://tools.ietf.org/html/rfc4443#section-3.4)
    #[derive(FromPrimitive)]
    pub enum ParameterProblemCode {
        ErroneousHeader    = 0,
        UnrecognizedNextHeader = 1,
        UnrecognizedOption = 2,
    }

    /// Defines icmp message types as defined in [RFC 4443](https://tools.ietf.org/html/rfc792)
    ///
    /// todo: figure out the invoking packet
    /// todo: support more message types
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
            let kind =
                FromPrimitive::from_u8(data[0]).expect(&*format!("Invalid icmp message type value '{}'", data[0]));

            match kind {
                Icmpv6MessageKind::EchoRequest => Ok(Icmpv6Packet::EchoRequest(IcmpCommon::try_from(data)?)),
                Icmpv6MessageKind::EchoReply => Ok(Icmpv6Packet::EchoReply(IcmpCommon::try_from(data)?)),
                _ => Err(NbugError::Packet(String::from(format!(
                    "unhandled message type '{}'",
                    data[0]
                )))),
            }
        }
    }

    impl ProtocolPacketHeader for Icmpv6Packet {
        fn header_length(&self) -> usize { 6 }

        fn protocol_type(&self) -> ProtocolNumber { ProtocolNumber::Ipv6Icmp }

        fn header_data(&self) -> Option<HashMap<&str, u64>> {
            let mut data = HashMap::<&str, u64>::new();

            data.insert(ICMP_KIND_KEY, self.message_kind() as u64);

            Some(data)
        }
    }
}
