use std::collections::HashMap;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use num_traits::FromPrimitive;

use crate::error::{NbugError, Result};
use crate::protocols::icmp::icmpv4::Icmpv4MessageKind;
use crate::protocols::icmp::icmpv6::Icmpv6MessageKind;
use crate::protocols::icmp::ICMP_KIND_KEY;
use crate::protocols::{ProtocolNumber, ProtocolPacketHeader};
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

enum PacketStatus {
    Ok, // the packet was received or not received as expected
    Received,
    NotReceived
}
/// A simple evaluation of single behavior, including a breakdown of any
/// specific steps required by the behavior.
pub struct BehaviorEvaluation<'a> {
    passed: bool,

    /// The statuses of individual packets / packet types of the behavior's protocol.
    packet_status: HashMap<&'a str, PacketStatus>,
}

impl<'a> Behavior {
    // todo: consider using static for less memory usage
    const ICMP_ECHO: &'a str = "Icmp Echo";
    const ICMP_REQUEST: &'a str = "Icmp Request";

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
    pub fn evaluate(&self, headers: Vec<&'a dyn ProtocolPacketHeader>) -> BehaviorEvaluation {
        match self.protocol {
            ProtocolNumber::Icmp => self.evaluate_icmp(headers),
            ProtocolNumber::Ipv6Icmp => self.evaluate_icmpv6(headers),
            ProtocolNumber::Tcp => todo!(),
            ProtocolNumber::Udp => todo!(),
            _ => todo!(),
        }
    }

    /// Test the given packet status map for the target keys, and add the [PacketStatus::NotReceived] if no entry found.
    fn insert_not_received(packet_status: &'a mut HashMap<&'a str, PacketStatus>, targets: &[&'a str]) {
        for s in targets {
            if packet_status.contains_key(s) {
                packet_status.insert(s, PacketStatus::NotReceived);
            }
        }
    }

    /// evaluate behavior as icmpv4
    fn evaluate_icmp(&self, headers: Vec<&'a dyn ProtocolPacketHeader>) -> BehaviorEvaluation {
        let mut passed = true;
        let mut packet_status = HashMap::<&str, PacketStatus>::new();

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

            let passing: bool;

            match icmp_kind {
                Icmpv4MessageKind::EchoReply => {
                    passing = self.direction == Direction::Both;
                    packet_status.insert(Self::ICMP_ECHO, if passing { PacketStatus::Ok } else { PacketStatus::Received });
                },
                Icmpv4MessageKind::EchoRequest => {
                    passing = self.direction != Direction::Out;
                    packet_status.insert(Self::ICMP_REQUEST, if passing { PacketStatus::Ok } else { PacketStatus::Received });
                },
                _ => passing = true, // doesn't necessarily mean the behavior has failed
            }

            passed &= passing;
        }

        Behavior::insert_not_received(&mut packet_status, &[Behavior::ICMP_ECHO, Behavior::ICMP_ECHO]);

        BehaviorEvaluation {
            passed,
            packet_status: std::default::Default::default(),
        }
    }

    /// evaluate behavior as icmpv6
    fn evaluate_icmpv6(&self, headers: Vec<&'a dyn ProtocolPacketHeader>) -> BehaviorEvaluation {
        let mut passed = true;
        let mut packet_status = HashMap::<&str, PacketStatus>::new();

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

            let passing: bool;

            match icmp_kind {
                Icmpv6MessageKind::EchoReply => {
                    passing = self.direction == Direction::Both;
                    packet_status.insert(Self::ICMP_ECHO, if passing { PacketStatus::Ok } else { PacketStatus::Received });
                },
                Icmpv6MessageKind::EchoRequest => {
                    passing = self.direction != Direction::Out;
                    packet_status.insert(Self::ICMP_REQUEST, if passing { PacketStatus::Ok } else { PacketStatus::Received });
                },
                _ => passing = true, // doesn't necessarily mean the behavior has failed
            }

            passed &= passing;
        }

        Behavior::insert_not_received(&mut packet_status, &[Behavior::ICMP_ECHO, Behavior::ICMP_ECHO]);

        BehaviorEvaluation {
            passed,
            packet_status: std::default::Default::default(),
        }
    }
}

/// A basic collector for [Behavior]s and their corresponding
/// [ProtocolPacketHeaders].
struct BehaviorCollector<'a> {
    behavior_map: HashMap<&'a Behavior, Vec<&'a dyn ProtocolPacketHeader>>,
}

impl<'a> BehaviorCollector<'a> {
    pub fn new() -> BehaviorCollector<'a> {
        BehaviorCollector {
            behavior_map: HashMap::new(),
        }
    }

    /// Insert a new behavior into the collector.
    pub fn insert_behavior(&mut self, behavior: &'a Behavior) -> Result<()> {
        self.behavior_map.insert(behavior, vec![]);

        Ok(())
    }

    /// Insert a new header to the collector, if no matching behavior is found
    /// Err is returned.
    pub fn insert_header(&mut self, header: &'a dyn ProtocolPacketHeader, src: Option<Addr>, dst: Addr) -> Result<()> {
        for (behavior, headers) in &mut self.behavior_map {
            if behavior.protocol == header.protocol_type() && behavior.src == src && behavior.dst == dst {
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

struct BehaviorReport<'a> {
    evaluations: Vec<BehaviorEvaluation<'a>>,
}

/// A collection of [BehaviorEvaluation]s
impl<'a> BehaviorReport<'a> {
    pub fn new() -> Self { BehaviorReport { evaluations: vec![] } }

    /// Add another evaluation to the report.
    pub fn add(&mut self, evaluation: BehaviorEvaluation<'a>) { self.evaluations.push(evaluation); }
}
