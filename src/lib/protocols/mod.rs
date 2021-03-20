use std::convert::TryFrom;
use crate::error::NbugError;

/// Defines many structs and packet serialization from raw packet data. These will largely focus on
/// packets headers, and will largely ignore any packet payloads, as they are largely irrelevant to
/// this project.
mod icmp;
mod ip;
mod ethernet;
mod udp;
mod tcp;

/// The protocols supported for behavior execution and analysis.s
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolType {
    Icmp,
    Icmpv6,

    Ipv4,
    Ipv6,

    Tcp,
    Udp,
}

impl TryFrom<u8> for ProtocolType {
    type Error = NbugError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(ProtocolType::Icmp),
            58 => Ok(ProtocolType::Icmpv6),

            4 => Ok(ProtocolType::Ipv4),
            41 => Ok(ProtocolType::Ipv6),

            6 => Ok(ProtocolType::Tcp),
            17 => Ok(ProtocolType::Udp),

            _ => Err(NbugError::Packet(String::from(format!("unsupported protocol assigned number {}", value))))
        }
    }
}

/// Trait for structs representing a packet for one of the protocols specified by [ProtocolType]
trait ProtocolPacket {
    /// Retrieve the total length of the packet header
    fn header_length(&self) -> usize;

    /// Return the total length of the packet header and data.
    fn length(&self) -> usize;

    /// Get the type of protocol.
    fn protocol_type(&self) -> ProtocolType;
}