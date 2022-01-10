use std::collections::hash_map::Iter;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::Addr;
use crate::behavior::Direction;
use crate::protocols::{ProtocolNumber, ProtocolPacket};
use crate::protocols::icmp::icmpv4::Icmpv4MessageKind;
use crate::protocols::icmp::icmpv6::Icmpv6MessageKind;
use crate::protocols::tcp::TcpControlBits;
use crate::protocols::udp::UdpPacket;

#[derive(Debug, Deserialize, Eq, Hash, Serialize, PartialEq)]
pub enum PacketStatus {
    Ok, // the packet was received or not received as expected
    Received,
    NotReceived,
}

impl ToString for PacketStatus {
    fn to_string(&self) -> String {
        match self {
            PacketStatus::Ok => "Ok",
            PacketStatus::Received => "Received",
            PacketStatus::NotReceived => "NotReceived",
        }
        .to_owned()
    }
}

/*struct BehaviorEvaluator {

}

impl BehaviorEvaluator {
        /// Determine if a list off packets satisfies the expected behavior, and
        /// build a description of which steps of the behavior passed  and which
        /// failed.
        pub fn evaluate(&self, packets: &[ProtocolPacket]) -> BehaviorEvaluation {
            match self.protocol {
                ProtocolNumber::Icmp => self.evaluate_icmp(packets),
                ProtocolNumber::Ipv6Icmp => self.evaluate_icmpv6(packets),
                ProtocolNumber::Tcp => self.evaluate_tcp(packets),
                ProtocolNumber::Udp => self.evaluate_udp(packets),
                _ => todo!(),
            }
        }

        /// evaluate behavior as icmpv4
        fn evaluate_icmp(&self, packets: &[ProtocolPacket]) -> BehaviorEvaluation {
            let mut has_request = false;
            let mut has_reply = false;

            for packet in packets.iter().filter(|p| p.header.protocol() == ProtocolNumber::Icmp) {
                let icmp = variant_extract!(&packet.header, ProtocolHeader::Icmpv4(icmp), icmp);

                match icmp.message_kind() {
                    Icmpv4MessageKind::EchoReply => has_request = true,
                    Icmpv4MessageKind::EchoRequest => has_reply = true,
                    _ => {},
                }
            }

            self.build_icmp_evaluation(has_reply, has_request)
        }

        /// evaluate behavior as icmpv6
        fn evaluate_icmpv6(&self, packets: &[ProtocolPacket]) -> BehaviorEvaluation {
            let mut has_request = false;
            let mut has_reply = false;

            for packet in packets
                .iter()
                .filter(|p| p.header.protocol() == ProtocolNumber::Ipv6Icmp)
            {
                let icmp = variant_extract!(&packet.header, ProtocolHeader::Icmpv6(icmp), icmp);

                match icmp.message_kind() {
                    Icmpv6MessageKind::EchoReply => has_request = true,
                    Icmpv6MessageKind::EchoRequest => has_reply = true,
                    _ => {},
                }
            }

            self.build_icmp_evaluation(has_reply, has_request)
        }

        fn build_icmp_evaluation(&self, has_reply: bool, has_request: bool) -> BehaviorEvaluation {
            let mut eval = BehaviorEvaluation::new(self.src, self.dst);

            match self.direction {
                Direction::Out => {
                    eval.insert_status(
                        Self::ICMP_ECHO_REPLY,
                        if has_reply {
                            PacketStatus::NotReceived
                        } else {
                            PacketStatus::Ok
                        },
                    );
                    eval.insert_status(
                        Self::ICMP_ECHO_REQUEST,
                        if has_request {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                },
                Direction::In => {
                    eval.insert_status(
                        Self::ICMP_ECHO_REPLY,
                        if has_reply {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );

                    // Receiving a request should not fail the behavior
                    eval.insert_status(
                        Self::ICMP_ECHO_REQUEST,
                        if has_request {
                            PacketStatus::Received
                        } else {
                            PacketStatus::Ok
                        },
                    );
                },
                Direction::Both => {
                    eval.insert_status(
                        Self::ICMP_ECHO_REPLY,
                        if has_reply {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                    eval.insert_status(
                        Self::ICMP_ECHO_REQUEST,
                        if has_request {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                },
            }

            eval
        }

        fn evaluate_tcp(&self, packets: &[ProtocolPacket]) -> BehaviorEvaluation {
            let mut has_syn = false;
            let mut has_syn_ack = false;
            let mut has_ack = false;

            for packet in packets.iter().filter(|p| p.header.protocol() == ProtocolNumber::Tcp) {
                let tcp = variant_extract!(&packet.header, ProtocolHeader::Tcp(tcp), tcp);
                let control_bits = TcpControlBits::find_control_bits(tcp.control_bits);

                if TcpControlBits::is_syn(&control_bits) {
                    has_syn = true;
                } else if TcpControlBits::is_syn_ack(&control_bits) {
                    has_syn_ack = true;
                } else if TcpControlBits::is_ack(&control_bits) {
                    has_ack = true;
                }
            }

            let mut eval = BehaviorEvaluation::new(self.src, self.dst);

            match self.direction {
                Direction::Out => {
                    // the initial syn would still be recorded on the network if not allowed out of
                    // the network,  but no other packets should be received
                    // todo: consider using protocols to find the direction of travel rather than
                    //   control bits?
                    eval.insert_status(
                        Self::TCP_SYN,
                        if has_syn {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                    eval.insert_status(
                        Self::TCP_SYN_ACK,
                        if has_syn_ack {
                            PacketStatus::Received
                        } else {
                            PacketStatus::Ok
                        },
                    );
                    eval.insert_status(
                        Self::TCP_ACK,
                        if has_ack {
                            PacketStatus::Received
                        } else {
                            PacketStatus::Ok
                        },
                    );
                },
                Direction::In => {
                    // you should see incoming Syn packets and the responding SynAck, but no other
                    // packets should be receivedd.
                    eval.insert_status(
                        Self::TCP_SYN,
                        if has_syn {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                    eval.insert_status(
                        Self::TCP_SYN_ACK,
                        if has_syn_ack {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                    eval.insert_status(
                        Self::TCP_ACK,
                        if has_ack {
                            PacketStatus::Received
                        } else {
                            PacketStatus::Ok
                        },
                    );
                },
                Direction::Both => {
                    // the initial syn would still be recorded on the network if not allowed out of
                    // the network
                    eval.insert_status(
                        Self::TCP_SYN,
                        if has_syn {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                    eval.insert_status(
                        Self::TCP_SYN_ACK,
                        if has_syn_ack {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                    eval.insert_status(
                        Self::TCP_ACK,
                        if has_ack {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                },
            }

            eval
        }

        fn evaluate_udp(&self, packets: &[ProtocolPacket]) -> BehaviorEvaluation {
            let mut has_egress = false;
            let mut has_ingress = false;

            let destination_port = self.dst.port().unwrap();

            for packet in packets.iter().filter(|p| p.header.protocol() == ProtocolNumber::Udp) {
                let header = &packet.header;
                let udp: &UdpPacket = variant_extract!(header, ProtocolHeader::Udp(udp), udp);

                if udp.destination_port == destination_port {
                    has_egress = true;
                } else {
                    has_ingress = true;
                }
            }

            let mut eval = BehaviorEvaluation::new(self.src, self.dst);

            match self.direction {
                Direction::Out => {
                    eval.insert_status(
                        Self::UDP_EGRESS,
                        if has_egress {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                    eval.insert_status(
                        Self::UDP_INGRESS,
                        if has_ingress {
                            PacketStatus::Received
                        } else {
                            PacketStatus::Ok
                        },
                    );
                },
                Direction::In => {
                    eval.insert_status(
                        Self::UDP_EGRESS,
                        if has_egress {
                            PacketStatus::Received
                        } else {
                            PacketStatus::Ok
                        },
                    );
                    eval.insert_status(
                        Self::UDP_INGRESS,
                        if has_ingress {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                },
                Direction::Both => {
                    eval.insert_status(
                        Self::UDP_EGRESS,
                        if has_egress {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                    eval.insert_status(
                        Self::UDP_INGRESS,
                        if has_ingress {
                            PacketStatus::Ok
                        } else {
                            PacketStatus::NotReceived
                        },
                    );
                },
            }

            eval
        }
    }
}*/

/// A simple evaluation of single behavior, including a breakdown of any
/// specific steps required by the behavior.
#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct BehaviorEvaluation<'a> {
    src: IpAddr,

    dst: Addr,

    /// The statuses of individual packets / packet types of the behavior's
    /// protocol.
    #[serde(borrow)]
    packet_status: HashMap<&'a str, PacketStatus>,
}

impl<'a> BehaviorEvaluation<'a> {
    pub fn new(src: IpAddr, dst: Addr) -> BehaviorEvaluation<'a> {
        BehaviorEvaluation {
            src,
            dst,
            packet_status: HashMap::new(),
        }
    }

    pub fn with_statuses(src: IpAddr, dst: Addr, packet_status: HashMap<&'a str, PacketStatus>) -> BehaviorEvaluation {
        BehaviorEvaluation {
            src,
            dst,
            packet_status,
        }
    }

    pub fn insert_status(&mut self, key: &'a str, status: PacketStatus) { self.packet_status.insert(key, status); }

    pub fn passed(&self) -> bool { self.packet_status.values().all(|status| *status == PacketStatus::Ok) }

    pub fn source(&self) -> IpAddr { self.src }

    pub fn destination(&self) -> Addr { self.dst }

    pub fn data(&self) -> Iter<'_, &'a str, PacketStatus> { self.packet_status.iter() }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct BehaviorReport<'a> {
    passing: usize,

    failing: usize,

    #[serde(borrow)]
    evaluations: Vec<BehaviorEvaluation<'a>>,
}

/// A collection of [BehaviorEvaluation]s
impl<'a> BehaviorReport<'a> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add another evaluation to the report.
    pub fn add(&mut self, evaluation: BehaviorEvaluation<'a>) {
        match evaluation.passed() {
            true => self.passing += 1,
            false => self.failing += 1,
        }

        self.evaluations.push(evaluation);
    }

    pub fn iter(&'a self) -> ReportIterator<'a> { ReportIterator::new(&self.evaluations) }
}

impl Default for BehaviorReport<'_> {
    fn default() -> Self {
        BehaviorReport {
            passing:     0,
            failing:     0,
            evaluations: vec![],
        }
    }
}

pub struct ReportIterator<'a> {
    evaluations: &'a [BehaviorEvaluation<'a>],
    index:       usize,
}

impl<'a> ReportIterator<'a> {
    pub fn new(evaluations: &'a [BehaviorEvaluation]) -> ReportIterator<'a> {
        ReportIterator { evaluations, index: 0 }
    }
}

impl<'a> Iterator for ReportIterator<'a> {
    type Item = &'a BehaviorEvaluation<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let eval = self.evaluations.get(self.index);

        if eval.is_some() {
            self.index += 1;
        }

        eval
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::str::FromStr;

    use crate::behavior::evaluate::{BehaviorEvaluation, PacketStatus};
    use crate::Addr;

    fn get_simple_eval() -> BehaviorEvaluation<'static> {
        BehaviorEvaluation::new(
            IpAddr::from_str("127.0.0.1").unwrap(),
            Addr::from_str("127.0.0.1").unwrap(),
        )
    }

    #[test]
    fn test_passed_empty() {
        let eval = get_simple_eval();

        assert!(eval.passed());
    }

    #[test]
    fn test_passed_simple() {
        let mut eval = get_simple_eval();

        eval.insert_status("PASSED", PacketStatus::Ok);
        eval.insert_status("ALSO_PASSED", PacketStatus::Ok);

        assert!(eval.passed());
    }

    #[test]
    fn test_failing_not_received() {
        let mut eval = get_simple_eval();

        eval.insert_status("NOT_RECEIVED", PacketStatus::NotReceived);

        assert!(!eval.passed());
    }

    #[test]
    fn test_failing_received() {
        let mut eval = get_simple_eval();

        eval.insert_status("RECEIVED", PacketStatus::Received);

        assert!(!eval.passed());
    }

    #[test]
    fn test_mixed() {
        let mut eval = get_simple_eval();

        eval.insert_status("RECEIVED", PacketStatus::Received);
        eval.insert_status("NOT_RECEIVED", PacketStatus::NotReceived);
        eval.insert_status("RECEIVED", PacketStatus::Received);

        assert!(!eval.passed());
    }
}
