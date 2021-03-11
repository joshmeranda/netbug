use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

mod icmp;
mod ip;

/// The protocols supported for behavior execution and analysis.s
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Icmp,
    IcmpV6,
    Tcp,
    Udp,
}

enum IeeEthernet {
    Ieee802_2(Ethernet2),
    Ieee802_3(Ethernet3),
}

/// The ethernet packet for IEE 802.2
struct Ethernet2 {
    destination: [u8; 6],

    source: [u8; 6],

    protocol: Protocol,
}

/// The ethernet packet for IEE 802.3
struct Ethernet3 {
    destination: [u8; 6],

    source: [u8; 6],

    length: u8,

    data: Vec<u8>,

    frame_check_sequence: u8
}

enum TcpControlBits {
    Rrg,
    Ack,
    Psh,
    Rst,
    Syn,
    Fin
}

/// The TCP Packet as specified in [RFC 793 3.1](https://tools.ietf.org/html/rfc793#section-3.1).
struct Tcp {
    source_port: u16,

    destination_port: u16,

    sequence_number: u32,

    acknowledgement_number: u32,

    offset: u8,

    control_bits: u8,

    window: u16,

    checksum: u16,

    urgent_pointer: u16
}

/// The UDP Packet a s specified in [RFC 768](https://tools.ietf.org/html/rfc768).
struct Udp {
    source_port: u16,

    destination_port: u16,

    length: u16,

    checksum: u16,
}