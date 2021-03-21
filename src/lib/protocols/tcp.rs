enum TcpControlBits {
    Rrg,
    Ack,
    Psh,
    Rst,
    Syn,
    Fin,
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

    urgent_pointer: u16,
}
