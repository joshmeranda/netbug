use std::convert::TryFrom;
use crate::error::NbugError;

/// Defines many structs and packet serialization from raw packet data. These will largely focus on
/// packets headers, and will largely ignore any packet payloads, as they are largely irrelevant to
/// this project.
mod icmp;
mod ip;
pub mod ethernet;
mod udp;
mod tcp;

/// The protocols supported for behavior execution and analysis.s
#[derive(Copy, Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Icmp,
    Icmpv6,

    Ipv4,
    Ipv6,

    Tcp,
    Udp,
}

impl TryFrom<u8> for Protocol {
    type Error = NbugError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Protocol::Icmp),
            58 => Ok(Protocol::Icmpv6),

            4 => Ok(Protocol::Ipv4),
            41 => Ok(Protocol::Ipv6),

            6 => Ok(Protocol::Tcp),
            17 => Ok(Protocol::Udp),

            _ => Err(NbugError::Packet(String::from(format!("unsupported protocol assigned number {}", value))))
        }
    }
}