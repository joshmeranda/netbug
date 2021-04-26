use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::{Shutdown, TcpStream, UdpSocket};
use std::process::Command;
use std::time::Duration;

use num_traits::FromPrimitive;

use crate::behavior::evaluate::BehaviorEvaluation;
use crate::config::defaults;
use crate::error::{NbugError, Result};
use crate::protocols::icmp::icmpv4::Icmpv4MessageKind;
use crate::protocols::icmp::icmpv6::Icmpv6MessageKind;
use crate::protocols::icmp::ICMP_KIND_KEY;
use crate::protocols::tcp::{TcpControlBits, CONTROL_BITS_KEY};
use crate::protocols::{ProtocolHeader, ProtocolNumber, ProtocolPacket, DST_PORT_KEY, SRC_PORT_KEY};
use crate::Addr;

pub mod collector;
pub mod evaluate;

use evaluate::PacketStatus;

use crate::protocols::udp::UdpPacket;

/// Simple macro to extract values from an enum struct variant. If only one
/// value is requested only that value is returned, if multiple are requested,
/// they are all returned as a tuple. This macro will panic if the supplied
/// `var` and `variant` are of difering types.
///
/// # Examples
/// ```
/// #  #[macro_use] extern crate netbug;
/// enum Sample {
///     Variant(usize, usize)
/// }
///
/// # fn main() {
/// let sample = Sample::Variant(0, 1);
/// assert_eq!(variant_extract!(sample, Sample::Variant(_, m), m), 1);
/// # }
/// ```
///
/// ```should_panic
/// #  #[macro_use] extern crate netbug;
/// enum Sample {
///     Variant(usize, usize)
/// }
///
/// # fn main() {
/// let sample = Sample::Variant(0, 1);
/// variant_extract!(sample, Some(n), m);
/// # }
/// ```
macro_rules! variant_extract {
    ($var:expr, $variant:pat, $data:ident) => {
        match $var {
            $variant => $data,
            _ => panic!("no such variant exists"),
        }
    };
    ($var:expr, $variant:pat, $($data:ident),+) => {
        match $var {
            $variant => ($($data),+),
            _ => panic!("no such variant exists")
        }
    };
}

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
    #[serde(default = "defaults::client::default_addr")]
    src: Addr,

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

    /// Determine if a list off packets satisfies the expected behavior, and
    /// build a description of which steps of the behavior passed  and which
    /// failed.
    pub fn evaluate(&self, packets: Vec<ProtocolPacket>) -> BehaviorEvaluation {
        match self.protocol {
            ProtocolNumber::Icmp => self.evaluate_icmp(packets),
            ProtocolNumber::Ipv6Icmp => self.evaluate_icmpv6(packets),
            ProtocolNumber::Tcp => self.evaluate_tcp(packets),
            ProtocolNumber::Udp => self.evaluate_udp(packets),
            _ => todo!(),
        }
    }

    /// evaluate behavior as icmpv4
    fn evaluate_icmp(&self, packets: Vec<ProtocolPacket>) -> BehaviorEvaluation {
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
    fn evaluate_icmpv6(&self, packets: Vec<ProtocolPacket>) -> BehaviorEvaluation {
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
        let mut eval = BehaviorEvaluation::new();

        match self.direction {
            Direction::Out => {
                eval.insert_status(
                    Self::ICMP_ECHO_REPLY,
                    if has_reply {
                        PacketStatus::Received
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

    fn evaluate_tcp(&self, packets: Vec<ProtocolPacket>) -> BehaviorEvaluation {
        let mut has_syn = false;
        let mut has_syn_ack = false;
        let mut has_ack = false;
        let mut has_fin = false;

        for packet in packets.iter().filter(|p| p.header.protocol() == ProtocolNumber::Tcp) {
            let tcp = variant_extract!(&packet.header, ProtocolHeader::Tcp(tcp), tcp);
            let control_bits = TcpControlBits::find_control_bits(tcp.control_bits);

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

        let mut eval = BehaviorEvaluation::new();

        match self.direction {
            Direction::Out | Direction::In => {
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
                eval.insert_status(
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
                eval.insert_status(
                    Self::TCP_FIN,
                    if has_fin {
                        PacketStatus::Ok
                    } else {
                        PacketStatus::NotReceived
                    },
                );
            },
        }

        eval
    }

    fn evaluate_udp(&self, packets: Vec<ProtocolPacket>) -> BehaviorEvaluation {
        let mut has_egress = false;
        let mut has_ingress = false;

        let behavior_src = if let Addr::Socket(addr) = self.src {
            addr.port()
        } else {
            0u16 // todo: consider failing or a better default source port
        };

        let behavior_dst = if let Addr::Socket(addr) = self.dst {
            addr.port()
        } else {
            0u16 // todo: consider failing or a better default source port
        };

        for packet in packets.iter().filter(|p| p.header.protocol() == ProtocolNumber::Udp) {
            let header = &packet.header;
            let udp: &UdpPacket = variant_extract!(header, ProtocolHeader::Udp(udp), udp);

            if udp.source_port == behavior_src && udp.destination_port == behavior_dst {
                has_egress = true;
            } else {
                has_ingress = true;
            }
        }

        let mut eval = BehaviorEvaluation::new();

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