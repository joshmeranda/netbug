use std::collections::HashMap;

use crate::behavior::evaluate::BehaviorReport;
use crate::behavior::Behavior;
use crate::error::{NbugError, Result};
use crate::protocols::{ProtocolHeader, ProtocolPacket};

/// A basic collector for [Behavior]s and their corresponding
/// [ProtocolPackets].
pub struct BehaviorCollector<'a> {
    behavior_map: HashMap<&'a Behavior, Vec<ProtocolPacket>>,
}

impl Default for BehaviorCollector<'_> {
    fn default() -> Self {
        BehaviorCollector {
            behavior_map: HashMap::new(),
        }
    }
}

impl<'a> BehaviorCollector<'a> {
    pub fn new() -> BehaviorCollector<'a> {
        Self::default()
    }

    pub fn with_behaviors(behaviors: &'a [&Behavior]) -> BehaviorCollector<'a> {
        let mut behavior_map = HashMap::new();

        for behavior in behaviors {
            behavior_map.insert(*behavior, vec![]);
        }

        BehaviorCollector { behavior_map }
    }

    /// Insert a new behavior into the collector.
    pub fn insert_behavior(&mut self, behavior: &'a Behavior) {
        self.behavior_map.insert(behavior, vec![]);
    }

    /// Insert a new header to the collector, if no matching behavior is found
    /// Err is returned.
    pub fn insert_packet(&mut self, packet: ProtocolPacket) -> Result<()> {
        for (behavior, packets) in &mut self.behavior_map {
            if BehaviorCollector::packet_matches(behavior, &packet) {
                packets.push(packet);

                return Ok(());
            }
        }

        Err(NbugError::Processing(format!(
            "no behavior matches header: {} src: {} and dst: {}",
            packet.header.protocol() as u8,
            packet.source.to_string(),
            packet.destination.to_string()
        )))
    }

    fn packet_matches(behavior: &'a Behavior, packet: &'a ProtocolPacket) -> bool {
        let destination_port = BehaviorCollector::get_destination_port(packet);
        let source_port = BehaviorCollector::get_source_port(packet);

        behavior.protocol == packet.header.protocol()
            && (behavior.dst.port() == destination_port || behavior.dst.port() == source_port)
            && ((behavior.src == packet.source.ip() && behavior.dst.ip() == packet.destination.ip())
                || behavior.dst.ip() == packet.source.ip() && behavior.src == packet.source.ip())
    }

    fn get_destination_port(packet: &'a ProtocolPacket) -> Option<u16> {
        match &packet.header {
            ProtocolHeader::Tcp(tcp) => Some(tcp.destination_port),
            ProtocolHeader::Udp(udp) => Some(udp.destination_port),
            _ => None,
        }
    }

    fn get_source_port(packet: &'a ProtocolPacket) -> Option<u16> {
        match &packet.header {
            ProtocolHeader::Tcp(tcp) => Some(tcp.source_port),
            ProtocolHeader::Udp(udp) => Some(udp.source_port),
            _ => None,
        }
    }

    /// Produce a comprehensive report on the behaviors gathered by the
    /// collector, but consumes the collector.
    pub fn evaluate(self) -> BehaviorReport<'a> {
        let mut report = BehaviorReport::new();

        for (behavior, packets) in self.behavior_map {
            let evaluation = behavior.evaluate(packets.as_slice());

            report.add(evaluation);
        }

        report
    }
}

#[cfg(test)]
mod test {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
    use std::str::FromStr;

    use crate::behavior::collector::BehaviorCollector;
    use crate::behavior::{Behavior, Direction};
    use crate::protocols::ethernet::{Ethernet2Packet, IeeEthernetPacket};
    use crate::protocols::icmp::icmpv4::Icmpv4Packet;
    use crate::protocols::icmp::icmpv6::Icmpv6Packet;
    use crate::protocols::icmp::IcmpCommon;
    use crate::protocols::ip::{IpPacket, Ipv4Packet, Ipv6Packet, ServiceType};
    use crate::protocols::tcp::{TcpControlBits, TcpPacket};
    use crate::protocols::udp::UdpPacket;
    use crate::protocols::{ProtocolHeader, ProtocolNumber, ProtocolPacket};
    use crate::Addr;

    static LOCAL_PORT: u16 = u16::MIN;

    static REMOTE_PORT: u16 = u16::MAX;

    fn get_icmp_packet() -> ProtocolPacket {
        ProtocolPacket {
            ether:       IeeEthernetPacket::Ieee8022(Ethernet2Packet::new([0; 6], [0; 6], ProtocolNumber::Icmp)),
            ip:          IpPacket::V4(Ipv4Packet {
                header_length:    0,
                service_type:     ServiceType::Routine,
                low_delay:        false,
                high_throughput:  false,
                high_reliability: false,
                total_length:     0,
                identification:   0,
                flags:            0,
                offset:           0,
                ttl:              0,
                protocol:         ProtocolNumber::Icmp,
                checksum:         0,
                source:           Ipv4Addr::new(127, 0, 0, 1),
                destination:      Ipv4Addr::new(127, 0, 0, 1),
            }),
            header:      ProtocolHeader::Icmpv4(Icmpv4Packet::EchoRequest(IcmpCommon {
                kind:       8,
                code:       0,
                checksum:   0,
                identifier: 0,
                sequence:   0,
            })),
            source:      Addr::from_str("127.0.0.1").unwrap(),
            destination: Addr::from_str("127.0.0.1").unwrap(),
        }
    }

    fn get_icmpv6_packet() -> ProtocolPacket {
        ProtocolPacket {
            ether:       IeeEthernetPacket::Ieee8022(Ethernet2Packet::new([0; 6], [0; 6], ProtocolNumber::Icmp)),
            ip:          IpPacket::V6(Ipv6Packet {
                traffic_class:  0,
                flow_label:     0,
                payload_length: 0,
                next_header:    ProtocolNumber::Ipv6Icmp,
                hop_limit:      0,
                source:         Ipv6Addr::from_str("::1").unwrap(),
                destination:    Ipv6Addr::from_str("::1").unwrap(),
            }),
            header:      ProtocolHeader::Icmpv6(Icmpv6Packet::EchoRequest(IcmpCommon {
                kind:       8,
                code:       0,
                checksum:   0,
                identifier: 0,
                sequence:   0,
            })),
            source:      Addr::from_str("::1").unwrap(),
            destination: Addr::from_str("::1").unwrap(),
        }
    }

    fn get_tcp_packet() -> ProtocolPacket {
        ProtocolPacket {
            ether:       IeeEthernetPacket::Ieee8022(Ethernet2Packet::new([0; 6], [0; 6], ProtocolNumber::Icmp)),
            ip:          IpPacket::V4(Ipv4Packet {
                header_length:    0,
                service_type:     ServiceType::Routine,
                low_delay:        false,
                high_throughput:  false,
                high_reliability: false,
                total_length:     0,
                identification:   0,
                flags:            0,
                offset:           0,
                ttl:              0,
                protocol:         ProtocolNumber::Tcp,
                checksum:         0,
                source:           Ipv4Addr::new(127, 0, 0, 1),
                destination:      Ipv4Addr::new(127, 0, 0, 1),
            }),
            header:      ProtocolHeader::Tcp(TcpPacket {
                source_port:            LOCAL_PORT,
                destination_port:       REMOTE_PORT,
                sequence_number:        0,
                acknowledgement_number: 0,
                offset:                 0,
                control_bits:           TcpControlBits::Syn as u8,
                window:                 0,
                checksum:               0,
                urgent_pointer:         0,
                options:                None,
            }),
            source:      Addr::from_str("127.0.0.1").unwrap(),
            destination: Addr::from_str("127.0.0.1").unwrap(),
        }
    }

    fn get_udp_packet() -> ProtocolPacket {
        ProtocolPacket {
            ether:       IeeEthernetPacket::Ieee8022(Ethernet2Packet::new([0; 6], [0; 6], ProtocolNumber::Icmp)),
            ip:          IpPacket::V4(Ipv4Packet {
                header_length:    0,
                service_type:     ServiceType::Routine,
                low_delay:        false,
                high_throughput:  false,
                high_reliability: false,
                total_length:     0,
                identification:   0,
                flags:            0,
                offset:           0,
                ttl:              0,
                protocol:         ProtocolNumber::Udp,
                checksum:         0,
                source:           Ipv4Addr::new(127, 0, 0, 1),
                destination:      Ipv4Addr::new(127, 0, 0, 1),
            }),
            header:      ProtocolHeader::Udp(UdpPacket {
                source_port:      REMOTE_PORT,
                destination_port: LOCAL_PORT,
                length:           0,
                checksum:         0,
            }),
            source:      Addr::from_str("127.0.0.1").unwrap(),
            destination: Addr::from_str("127.0.0.1").unwrap(),
        }
    }

    #[test]
    fn test_packet_matches_icmp() {
        let behavior = Behavior {
            src:       IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst:       Addr::Internet(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            protocol:  ProtocolNumber::Icmp,
            direction: Direction::Both,
            timeout:   None,
            command:   None,
        };

        assert!(BehaviorCollector::packet_matches(&behavior, &get_icmp_packet()));
        assert!(!BehaviorCollector::packet_matches(&behavior, &get_icmpv6_packet()));
        assert!(!BehaviorCollector::packet_matches(&behavior, &get_tcp_packet()));
        assert!(!BehaviorCollector::packet_matches(&behavior, &get_udp_packet()));
    }

    #[test]
    fn test_packet_matches_icmpv6() {
        let behavior = Behavior {
            src:       IpAddr::V6(Ipv6Addr::from_str("::1").unwrap()),
            dst:       Addr::Internet(IpAddr::V6(Ipv6Addr::from_str("::1").unwrap())),
            protocol:  ProtocolNumber::Ipv6Icmp,
            direction: Direction::Both,
            timeout:   None,
            command:   None,
        };

        assert!(!BehaviorCollector::packet_matches(&behavior, &get_icmp_packet()));
        assert!(BehaviorCollector::packet_matches(&behavior, &get_icmpv6_packet()));
        assert!(!BehaviorCollector::packet_matches(&behavior, &get_tcp_packet()));
        assert!(!BehaviorCollector::packet_matches(&behavior, &get_udp_packet()));
    }

    #[test]
    fn test_packet_matches_tcp() {
        let behavior = Behavior {
            src:       IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst:       Addr::Socket(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                REMOTE_PORT,
            ))),
            protocol:  ProtocolNumber::Tcp,
            direction: Direction::Both,
            timeout:   None,
            command:   None,
        };

        assert!(!BehaviorCollector::packet_matches(&behavior, &get_icmp_packet()));
        assert!(!BehaviorCollector::packet_matches(&behavior, &get_icmpv6_packet()));
        assert!(BehaviorCollector::packet_matches(&behavior, &get_tcp_packet()));
        assert!(!BehaviorCollector::packet_matches(&behavior, &get_udp_packet()));
    }

    #[test]
    fn test_packet_matches_udp() {
        let behavior = Behavior {
            src:       IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            dst:       Addr::Socket(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(127, 0, 0, 1),
                REMOTE_PORT,
            ))),
            protocol:  ProtocolNumber::Udp,
            direction: Direction::In,
            timeout:   None,
            command:   None,
        };

        assert!(!BehaviorCollector::packet_matches(&behavior, &get_icmp_packet()));
        assert!(!BehaviorCollector::packet_matches(&behavior, &get_icmpv6_packet()));
        assert!(!BehaviorCollector::packet_matches(&behavior, &get_tcp_packet()));
        assert!(BehaviorCollector::packet_matches(&behavior, &get_udp_packet()));
    }
}
