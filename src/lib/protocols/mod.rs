/// Defines many structs and packet serialization from raw packet data. These will largely focus on
/// packets headers, and will largely ignore any packet payloads, as they are largely irrelevant to
/// this project.
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod icmp;
mod ip;
mod ethernet;
mod udp;
mod tcp;

/// The protocols supported for behavior execution and analysis.s
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Icmp,
    IcmpV6,
    Tcp,
    Udp,
}