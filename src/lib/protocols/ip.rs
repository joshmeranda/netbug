use crate::protocols::Protocol;
use std::net::{Ipv4Addr, Ipv6Addr};

enum IpPacket {
    V4(Ipv4Packet),
    V6(Ipv6Packet)
}

enum ServiceType {
    Routine,
    Priority,
    Immediate,
    Flash,
    FlashOverride,
    CriticEcp,
    InternetworkControl,
    NetworkControl,
}

/// The IPv4 Packet header as specified in [RFC 791](https://tools.ietf.org/html/rfc791#section-3.1).
struct Ipv4Packet {
    header_length: u8,

    // todo: consider making enum
    service_type: u8,

    total_length: u16,

    identification: u16,

    flags: u8,

    offset: u16,

    ttl: u8,

    protocol: Protocol,

    checksum: u16,

    source: Ipv4Addr,

    destination: Ipv4Addr
}

/// Ipv6 Packet Header as specified in [RFC 8200](https://tools.ietf.org/html/rfc8200#section-3).
///
/// todo: support for extension headers
struct Ipv6Packet {
    // todo: consider making enum
    traffic_class: u8,

    flow_label: u32,

    payload_length: u16,

    next_header: Protocol,

    hop_limit: u8,

    source: Ipv6Addr,

    destination: Ipv6Addr
}