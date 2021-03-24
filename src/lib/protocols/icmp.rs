use std::convert::TryFrom;
/// Defines types relating to the Internet Control Message Protocol (ICMP)
/// versions 4 and 6. These types will largely ignore packet data as they will
/// be used for netbug analysis which does not require knowledge of packet
/// payloads.
use std::net::Ipv4Addr;

use crate::error::NbugError;
use crate::protocols::icmp::icmpv4::Icmpv4Packet;
use crate::protocols::icmp::icmpv6::Icmpv6Packet;

enum IcmpPacket {
    V4(Icmpv4Packet),
    V6(Icmpv6Packet),
}

mod icmpv4 {
    use std::net::Ipv4Addr;

    use crate::protocols::ip::Ipv4Packet;

    /// Maps variants to icmp message types as defined in [RFC 792 Summary of Message Types](https://tools.ietf.org/html/rfc792#page-20)
    #[derive(FromPrimitive)]
    enum Icmpv4MessageKind {
        EchoReply = 0,
        DestinationUnreachable = 3,
        SourceQuench = 4,
        Redirect  = 5,
        EchoRequest = 8,
        TimeExceeded = 11,
        ParameterProblem = 12,
        TimestampRequest = 13,
        TimestampReply = 14,
        InformationRequest = 15,
        InformationReply = 16,
    }

    /// Defines the variants of icmp v4 packets as defined in [RFC 792](https://tools.ietf.org/html/rfc792)
    pub enum Icmpv4Packet {
        /// Described in [RFC 792 Pg 14](https://tools.ietf.org/html/rfc792#page-14)
        EchoReply {
            checksum:        u16,
            identifier:      u16,
            sequence_number: u16,
        },

        /// Described in [RFC 792 Pg 4](https://tools.ietf.org/html/rfc792#page-4)
        DestinationUnreachable {
            checksum:        u16,
            internet_header: Ipv4Packet,
        },

        /// Described in [RFC 792 Pg 10](https://tools.ietf.org/html/rfc792#page-10)
        SourceQuench {
            checksum:        u16,
            internet_header: Ipv4Packet,
        },

        /// Described in [RFC 792 Pg 12](https://tools.ietf.org/html/rfc792#page-12)
        Redirect {
            checksum:        u16,
            gateway_address: Ipv4Addr,
        },

        /// Described in [RFC 792 Pg 14](https://tools.ietf.org/html/rfc792#page-14)
        EchoRequest {
            checksum:        u16,
            identifier:      u16,
            sequence_number: u16,
        },

        /// Described in [RFC 792 Pg 6](https://tools.ietf.org/html/rfc792#page-6)
        TimeExceeded {
            checksum:        u16,
            internet_header: Ipv4Packet,
        },

        /// Described in [RFC 792 Pg 8](https://tools.ietf.org/html/rfc792#page-8)
        ParameterProblem {
            checksum:        u16,
            pointer:         u8,
            internet_header: Ipv4Packet,
        },

        /// Described in [RFC 792 Pg 16](https://tools.ietf.org/html/rfc792#page-16)
        TimestampRequest {
            checksum:           u16,
            identifier:         u16,
            sequence_number:    u16,
            original_timestamp: u32,
            receive_timestamp:  u32,
            transmit_timestamp: u32,
        },

        /// Described in [RFC 792 Pg 16](https://tools.ietf.org/html/rfc792#page-16)
        TimestampReply {
            checksum:           u16,
            identifier:         u16,
            sequence_number:    u16,
            original_timestamp: u32,
            receive_timestamp:  u32,
            transmit_timestamp: u32,
        },

        /// Described in [RFC 792 Pg 16](https://tools.ietf.org/html/rfc792#page-18)
        InformationRequest {
            checksum:        u16,
            identifier:      u16,
            sequence_number: u16,
        },

        /// Described in [RFC 792 Pg 16](https://tools.ietf.org/html/rfc792#page-18)
        InformationReply {
            checksum:        u16,
            identifier:      u16,
            sequence_number: u16,
        },
    }
}

mod icmpv6 {
    use std::convert::TryFrom;

    use num_traits::FromPrimitive;

    use crate::error::NbugError;

    /// Map variants to icmp v6 message types as defined in [RFC 4443 2.1](https://tools.ietf.org/html/rfc4443#section-2.1).
    #[derive(FromPrimitive)]
    pub enum Icmpv6MessageKind {
        DestinationUnreachable = 1,
        PacketTooBig = 2,
        TimeExceeded = 3,
        ParameterProblem = 4,
        PrivateExperimentationError1 = 100,
        PrivateExperimentationError2 = 101,
        ReservedForErrorExpansion = 127,

        EchoRequest = 128,
        EchoReply = 129,
        PrivateExperimentationInformational1 = 200,
        PrivateExperimentationInformational2 = 201,
        ReservedForInformationalExpansion = 255,
    }

    /// As defined in [RFC 4443 Section 3.1](https://tools.ietf.org/html/rfc4443#section-3.1)
    #[derive(FromPrimitive)]
    enum DestinationUnreachableCode {
        NoRoute    = 0,
        Prohibited = 1,
        BeyondScope = 2,
        AddressUnreachable = 3,
        PortUnreachable = 4,
        FailedTrafficPolicy = 5,
        RejectedRoute = 6,
    }

    /// As defined in [RFC 443 Section 3.3](https://tools.ietf.org/html/rfc4443#section-3.3)
    #[derive(FromPrimitive)]
    enum TimeExceededCode {
        HopLimitExceeded = 0,
        FragmentReassemblyExceeded = 1,
    }

    /// As defined in [RFC 443 Section 3.4](https://tools.ietf.org/html/rfc4443#section-3.4)
    #[derive(FromPrimitive)]
    enum ParameterProblemCode {
        ErroneousHeader = 0,
        UnrecognizedNextHeader = 1,
        UnrecognizedOption = 2,
    }

    /// Simple wrapper around an icmp echo and reply packet as defined in [RFC 4443 4.1](https://tools.ietf.org/html/rfc4443#section-4.1).
    struct IcmpEcho {
        checksum:   u16,
        identifier: u16,
        sequence:   u16,
    }

    /// Defines icmp message types as defined in [RFC 4443](https://tools.ietf.org/html/rfc792)
    ///
    /// todo: figure out the invoking packet
    /// todo: support more message types
    pub enum Icmpv6Packet {
        EchoRequest(IcmpEcho),

        EchoReply(IcmpEcho),
    }

    impl TryFrom<&[u8]> for Icmpv6Packet {
        type Error = NbugError;

        fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
            let kind = if let Some(type_val) = FromPrimitive::from_u8(data[0]) {
                type_val
            } else {
                return Err(NbugError::Packet(String::from(format!(
                    "Invalid icmp message type value '{}'",
                    data[0]
                ))));
            };

            match kind {
                Icmpv6MessageKind::EchoRequest => Ok(Icmpv6Packet::EchoRequest(IcmpEcho::try_from(data)?)),
                Icmpv6MessageKind::EchoReply => Ok(Icmpv6Packet::EchoReply(IcmpEcho::try_from(data)?)),
                _ => Err(NbugError::Packet(String::from(format!(
                    "unhandled message type '{}'",
                    data[0]
                )))),
            }
        }
    }

    impl TryFrom<&[u8]> for IcmpEcho {
        type Error = NbugError;

        fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
            if data.len() < 6 {
                return Err(NbugError::Packet(String::from(format!(
                    "Too few bytes, expected at least {}",
                    data.len()
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

            Ok(IcmpEcho {
                checksum,
                identifier,
                sequence,
            })
        }
    }
}
