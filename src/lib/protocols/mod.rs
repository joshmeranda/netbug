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

    Unknown
}

impl Protocol {
    pub fn from_ethernet_type(val: u16) -> Protocol {
        match val {
            0x08_00 => Protocol::Ipv4,
            0x86_dd => Protocol::Ipv6,
            _ => Protocol::Unknown
        }
    }
}