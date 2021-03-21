/// Defines types relating to the Internet Control Message Protocol (ICMP)
/// versions 4 and 6. These types will largely ignore packet data as they will
/// be used for netbug analysis which does not require knowledge of packet
/// payloads.
use std::net::Ipv4Addr;

enum Icmp {
    V4(Icmpv4),
    V6(Icmpv6),
}

/// The ICMPv4 packet as specified in [RFC 791](https://tools.ietf.org/html/rfc792).
struct Icmpv4 {
    header_length: u8,

    total_length: u16,

    identification: u16,

    flags: u8,

    offset: u16,

    ttl: u8,

    checksum: u16,

    source: Ipv4Addr,

    destination: Ipv4Addr,
}

/// Defines the available types of ICMPv6 messages.
///
/// todo: convert to and from u8
enum Icmpv6 {
    // Errors
    DestinationUnrecheable(Icmpv6Header),

    PacketTooBig(Icmpv6Header),

    TimeExceeded(Icmpv6Header),

    ParameterProblem(Icmpv6Header),

    // Informational
    EchoRequest(Icmpv6Header, Icmpv6EchoRequest),

    EchoReply(Icmpv6Header, Icmpv6EchoReply),
}

/// The generic ICMPv6 packet header as specified in [RFC 4443 2.1](https://tools.ietf.org/html/rfc4443#section-2.1).
struct Icmpv6Header {
    code: u8,

    checksum: u16,
}

/// The ICMPv6 Echo Request as specified in [RFC 4443 4.1](https://tools.ietf.org/html/rfc4443#section-4.1)
struct Icmpv6EchoRequest {
    identifier: u16,

    sequence_number: u16,
}

/// The ICMPv6 Echo Reply as specified in [RFC 4443 4.2](https://tools.ietf.org/html/rfc4443#section-4.2)
struct Icmpv6EchoReply {
    identifier: u16,

    sequence_number: u16,
}
