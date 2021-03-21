/// The UDP Packet a s specified in [RFC 768](https://tools.ietf.org/html/rfc768).
struct Udp {
    source_port: u16,

    destination_port: u16,

    length: u16,

    checksum: u16,
}
