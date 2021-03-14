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

    Ip,
    Ipv6,

    Tcp,
    Udp,

    Unknown
}