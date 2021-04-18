use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::{Shutdown, TcpStream, UdpSocket};
use std::process::Command;
use std::time::Duration;

use num_traits::FromPrimitive;

use crate::error::{NbugError, Result};
use crate::protocols::icmp::icmpv4::Icmpv4MessageKind;
use crate::protocols::icmp::icmpv6::Icmpv6MessageKind;
use crate::protocols::icmp::ICMP_KIND_KEY;
use crate::protocols::tcp::{TcpControlBits, CONTROL_BITS_KEY};
use crate::protocols::{ProtocolNumber, ProtocolPacketHeader, DST_PORT_KEY, SRC_PORT_KEY};
use crate::Addr;

/// Specifies the direction traffic should be expected. When used in the client
/// configuration, this field is ignored and will have no effect.
///
/// # Example
/// For a Tcp connection's 3-way-handshake:
///  - In: Will always fail because no Ack will be received without the initial
///    Syn
///  - Out: Will fail if the client receives and Ack for its Syn
///  - Both: Will fail if one part of the handshake is not received
#[derive(Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
enum Direction {
    In,
    Out,
    Both,
}

impl Default for Direction {
    fn default() -> Direction { Direction::Both }
}

/// A basic behavior to emulate the type of traffic
/// todo: provide an optional description
#[derive(Deserialize, PartialEq, Eq, Hash)]
pub struct Behavior {
    src: Option<Addr>,

    dst: Addr,

    #[serde(rename = "protocol")]
    protocol: ProtocolNumber,

    #[serde(default = "std::default::Default::default")]
    direction: Direction,

    timeout: Option<Duration>,

    /// The optional user specified command to cause the specific behavior
    /// rather than allowing netbug to take the appropriate actions. The
    /// first element is the command or path to executable to run, and the
    /// following elements are the arguments to pass to it.
    command: Option<Vec<String>>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq, Hash)]
enum PacketStatus {
    Ok, // the packet was received or not received as expected
    Received,
    NotReceived,
}

/// A simple evaluation of single behavior, including a breakdown of any
/// specific steps required by the behavior.
#[derive(Serialize)]
pub struct BehaviorEvaluation<'a> {
    /// The statuses of individual packets / packet types of the behavior's
    /// protocol.
    packet_status: HashMap<&'a str, PacketStatus>,
}

impl BehaviorEvaluation<'_> {
    pub fn passed(&self) -> bool { self.packet_status.values().all(|status| *status == PacketStatus::Ok) }
}

impl<'a> Behavior {
    // todo: consider using static for less memory usage
    const ICMP_ECHO_REPLY: &'a str = "Icmp Echo Reply";
    const ICMP_ECHO_REQUEST: &'a str = "Icmp Echo Request";

    const TCP_SYN: &'a str = "TcpSyn";
    const TCP_ACK: &'a str = "TcpAck";
    const TCP_SYN_ACK: &'a str = "TcpSynAck";
    const TCP_FIN: &'a str = "TcpFin";

    const UDP_INGRESS: &'a str = "UdpIngress";
    const UDP_EGRESS: &'a str = "UdpEgress";

    /// Execute the behavior.
    /// todo: redirect stdout for commands
    pub fn run(&self) -> Result<()> {
        let timeout = if let Some(duration) = self.timeout {
            duration
        } else {
            Duration::from_secs(1)
        };

        if let Some(command) = &self.command {
            let mut handle = Command::new(&command[0]).args(&command.as_slice()[1..]).spawn()?;
            handle.wait()?;

            return Ok(());
        }

        match self.protocol {
            ProtocolNumber::Icmp => {
                let mut handle = Command::new("ping").args(&["-c", "1", &self.dst.to_string()]).spawn()?;
                handle.wait()?;
            },

            ProtocolNumber::Ipv6Icmp => {
                let mut handle = Command::new("ping")
                    .args(&["-6", "-c", "1", &self.dst.to_string()])
                    .spawn()?;
                handle.wait()?;
            },

            ProtocolNumber::Tcp => {
                let addr = match self.dst {
                    Addr::Socket(addr) => addr,
                    _ => return Err(NbugError::Client(String::from("Expected socket address for behavior"))),
                };

                let sock = TcpStream::connect_timeout(&addr, timeout).unwrap();

                sock.shutdown(Shutdown::Both)?;
            },

            ProtocolNumber::Udp => {
                let addr = match self.dst {
                    Addr::Socket(addr) => addr,
                    _ => return Err(NbugError::Client(String::from("Expected socket address for behavior"))),
                };

                let socket = UdpSocket::bind(&addr).unwrap();

                socket.send(&[])?;
            },

            _ =>
                return Err(NbugError::Client(String::from(format!(
                    "found unsupported protocol number: {}",
                    self.protocol as u8
                )))),
        };

        Ok(())
    }

    /// Determine if a list off packet headers satisfies the expected behavior,
    /// and build a description of which steps of the behavior passed  and which
    /// failed.
    pub fn evaluate(&self, headers: Vec<Box<dyn ProtocolPacketHeader>>) -> BehaviorEvaluation {
        match self.protocol {
            ProtocolNumber::Icmp => self.evaluate_icmp(headers),
            ProtocolNumber::Ipv6Icmp => self.evaluate_icmpv6(headers),
            ProtocolNumber::Tcp => todo!(),
            ProtocolNumber::Udp => todo!(),
            _ => todo!(),
        }
    }

    /// evaluate behavior as icmpv4
    fn evaluate_icmp(&self, headers: Vec<Box<dyn ProtocolPacketHeader>>) -> BehaviorEvaluation {
        let mut has_request = false;
        let mut has_reply = false;

        for header in headers {
            let data = if let Some(data) = header.header_data() {
                data
            } else {
                continue;
            };

            if !data.contains_key(ICMP_KIND_KEY) {
                continue;
            }

            let icmp_kind: Icmpv4MessageKind = FromPrimitive::from_u64(*data.get(ICMP_KIND_KEY).unwrap()).unwrap();

            match icmp_kind {
                Icmpv4MessageKind::EchoReply => has_request = true,
                Icmpv4MessageKind::EchoRequest => has_reply = true,
                _ => {},
            }
        }

        self.build_icmp_evaluation(has_reply, has_request)
    }

    /// evaluate behavior as icmpv6
    fn evaluate_icmpv6(&self, headers: Vec<Box<dyn ProtocolPacketHeader>>) -> BehaviorEvaluation {
        let mut has_request = false;
        let mut has_reply = false;

        for header in headers {
            let data = if let Some(data) = header.header_data() {
                data
            } else {
                continue;
            };

            if !data.contains_key(ICMP_KIND_KEY) {
                continue;
            }

            let icmp_kind: Icmpv6MessageKind = FromPrimitive::from_u64(*data.get(ICMP_KIND_KEY).unwrap()).unwrap();

            match icmp_kind {
                Icmpv6MessageKind::EchoReply => has_request = true,
                Icmpv6MessageKind::EchoRequest => has_reply = true,
                _ => {},
            }
        }

        self.build_icmp_evaluation(has_reply, has_request)
    }

    fn build_icmp_evaluation(&self, has_reply: bool, has_request: bool) -> BehaviorEvaluation {
        let mut packet_status = HashMap::<&str, PacketStatus>::new();

        match self.direction {
            Direction::Out => {
                packet_status.insert(
                    Self::ICMP_ECHO_REPLY,
                    if has_reply {
                        PacketStatus::Received
                    } else {
                        PacketStatus::Ok
                    },
                );
                packet_status.insert(
                    Self::ICMP_ECHO_REQUEST,
                    if has_request {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
            },
            Direction::In => {
                packet_status.insert(
                    Self::ICMP_ECHO_REPLY,
                    if has_reply {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );

                // Receiving a request should not fail the behavior
                packet_status.insert(
                    Self::ICMP_ECHO_REQUEST,
                    if has_request {
                        PacketStatus::Received
                    } else {
                        PacketStatus::Ok
                    },
                );
            },
            Direction::Both => {
                packet_status.insert(
                    Self::ICMP_ECHO_REPLY,
                    if has_reply {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
                packet_status.insert(
                    Self::ICMP_ECHO_REQUEST,
                    if has_request {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
            },
        }

        BehaviorEvaluation { packet_status }
    }

    fn evaluate_tcp(&self, headers: Vec<Box<dyn ProtocolPacketHeader>>) -> BehaviorEvaluation {
        let mut has_syn = false;
        let mut has_syn_ack = false;
        let mut has_ack = false;
        let mut has_fin = false;

        for header in headers {
            let data = if let Some(data) = header.header_data() {
                data
            } else {
                continue;
            };

            if !data.contains_key(CONTROL_BITS_KEY) {
                continue;
            }

            let control_bits =
                TcpControlBits::find_control_bits(u8::try_from(*data.get(CONTROL_BITS_KEY).unwrap()).unwrap());

            if TcpControlBits::is_syn(&control_bits) {
                has_syn = true;
            } else if TcpControlBits::is_syn_ack(&control_bits) {
                has_syn_ack = true;
            } else if TcpControlBits::is_ack(&control_bits) {
                has_ack = true;
            } else if TcpControlBits::is_fin(&control_bits) {
                has_fin = true;
            }
        }

        let mut packet_status = HashMap::<&str, PacketStatus>::new();

        match self.direction {
            Direction::Out | Direction::In => {
                // the initial syn would still be recorded on the network if not allowed out of
                // the network
                packet_status.insert(
                    Self::TCP_SYN,
                    if has_syn {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
                packet_status.insert(
                    Self::TCP_SYN_ACK,
                    if has_syn_ack {
                        PacketStatus::Received
                    } else {
                        PacketStatus::Ok
                    },
                );
                packet_status.insert(
                    Self::TCP_ACK,
                    if has_ack {
                        PacketStatus::Received
                    } else {
                        PacketStatus::Ok
                    },
                );
                packet_status.insert(
                    Self::TCP_FIN,
                    if has_fin {
                        PacketStatus::Received
                    } else {
                        PacketStatus::Ok
                    },
                );
            },
            Direction::Both => {
                // the initial syn would still be recorded on the network if not allowed out of
                // the network
                packet_status.insert(
                    Self::TCP_SYN,
                    if has_syn {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
                packet_status.insert(
                    Self::TCP_SYN_ACK,
                    if has_syn_ack {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
                packet_status.insert(
                    Self::TCP_ACK,
                    if has_ack {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
                packet_status.insert(
                    Self::TCP_FIN,
                    if has_fin {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
            },
        }

        BehaviorEvaluation { packet_status }
    }

    fn evaluate_udp(&self, headers: Vec<Box<dyn ProtocolPacketHeader>>) -> BehaviorEvaluation {
        let mut has_egress = false;
        let mut has_ingress = false;

        let behavior_src = if let Some(Addr::Socket(addr)) = self.src {
            addr.port() as u64
        } else {
            0u64 // todo: consider failing or a better default source port
        };

        let behavior_dst = if let Addr::Socket(addr) = self.dst {
            addr.port() as u64
        } else {
            0u64 // todo: consider failing or a better default source port
        };

        for header in headers {
            let data = if let Some(data) = header.header_data() {
                data
            } else {
                continue;
            };

            if !data.contains_key(SRC_PORT_KEY) || !data.contains_key(DST_PORT_KEY) {
                continue;
            }

            let packet_src = data.get(SRC_PORT_KEY).unwrap();
            let packet_dst = data.get(DST_PORT_KEY).unwrap();

            if *packet_src == behavior_src && *packet_dst == behavior_dst {
                has_egress = true;
            } else {
                has_ingress = true;
            }
        }

        let mut packet_status = HashMap::<&str, PacketStatus>::new();

        match self.direction {
            Direction::Out => {
                packet_status.insert(
                    Self::UDP_EGRESS,
                    if has_egress {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
                packet_status.insert(
                    Self::UDP_INGRESS,
                    if has_ingress {
                        PacketStatus::Received
                    } else {
                        PacketStatus::Ok
                    },
                );
            },
            Direction::In => {
                packet_status.insert(
                    Self::UDP_EGRESS,
                    if has_egress {
                        PacketStatus::Received
                    } else {
                        PacketStatus::Ok
                    },
                );
                packet_status.insert(
                    Self::UDP_INGRESS,
                    if has_ingress {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
            },
            Direction::Both => {
                packet_status.insert(
                    Self::UDP_EGRESS,
                    if has_egress {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
                packet_status.insert(
                    Self::UDP_INGRESS,
                    if has_ingress {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
            },
        }

        BehaviorEvaluation { packet_status }
    }
}

/// A basic collector for [Behavior]s and their corresponding
/// [ProtocolPacketHeaders].
pub struct BehaviorCollector<'a> {
    // todo: this vector probably takes up a lot of heap space and will cause a performance hit
    behavior_map: HashMap<&'a Behavior, Vec<Box<dyn ProtocolPacketHeader>>>,
}

impl<'a> BehaviorCollector<'a> {
    pub fn new() -> BehaviorCollector<'a> {
        BehaviorCollector {
            behavior_map: HashMap::new(),
        }
    }

    pub fn with_behaviors(behaviors: &'a [&Behavior]) -> BehaviorCollector<'a> {
        let mut behavior_map = HashMap::new();

        for behavior in behaviors {
            behavior_map.insert(*behavior, vec![]);
        }

        BehaviorCollector { behavior_map }
    }

    /// Insert a new behavior into the collector.
    pub fn insert_behavior(&mut self, behavior: &'a Behavior) -> Result<()> {
        self.behavior_map.insert(behavior, vec![]);

        Ok(())
    }

    /// Insert a new header to the collector, if no matching behavior is found
    /// Err is returned.
    pub fn insert_header(&mut self, header: Box<dyn ProtocolPacketHeader>, src: Option<Addr>, dst: Addr) -> Result<()> {
        for (behavior, headers) in &mut self.behavior_map {
            // todo: better handle more protocols like tcp, udp, etc
            if behavior.protocol == header.protocol_type()
                && (behavior.src == src && behavior.dst == dst
                    || behavior.src == Some(dst) && Some(behavior.dst) == src)
            {
                headers.push(header);

                return Ok(());
            }
        }

        Err(NbugError::Processing(String::from(format!(
            "no behavior matches header: {} src: {} and dst: {}",
            header.protocol_type() as u8,
            if let Some(s) = src {
                s.to_string()
            } else {
                String::from("None")
            },
            dst.to_string()
        ))))
    }

    /// Produce a comprehensive report on the behaviors gathered by the
    /// collector, but consumes the collector.
    pub fn evaluate(self) -> BehaviorReport<'a> {
        let mut report = BehaviorReport::new();

        for (behavior, headers) in self.behavior_map {
            let evaluation = behavior.evaluate(headers);

            report.add(evaluation);
        }

        report
    }
}

#[derive(Serialize)]
pub struct BehaviorReport<'a> {
    passing: usize,

    failing: usize,

    evaluations: Vec<BehaviorEvaluation<'a>>,
}

/// A collection of [BehaviorEvaluation]s
impl<'a> BehaviorReport<'a> {
    pub fn new() -> Self {
        BehaviorReport {
            passing:     0,
            failing:     0,
            evaluations: vec![],
        }
    }

    /// Add another evaluation to the report.
    pub fn add(&mut self, evaluation: BehaviorEvaluation<'a>) {
        match evaluation.passed() {
            true => self.passing += 1,
            false => self.failing += 1,
        }

        self.evaluations.push(evaluation);
    }
}
