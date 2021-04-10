use std::collections::HashMap;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use crate::error::{NbugError, Result};
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

impl Behavior {
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
    pub fn evaluate<'a>(&self, _headers: Vec<&'a dyn ProtocolPacketHeader>) -> BehaviorEvaluation { todo!() }
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
    pub fn evaluate(self) -> BehaviorReport {
        let mut report = BehaviorReport::new();

        for (behavior, headers) in self.behavior_map {
            let evaluation = behavior.evaluate(headers);

            report.add(evaluation);
        }

        report
    }
}

enum BehaviorStatus {
    Pass,
    Fail,

    Received,
    NotReceived,
}

/// A simple evaluation of single behavior, including a breakdown of any
/// specific steps required by the behavior.
pub struct BehaviorEvaluation {
    result: BehaviorStatus,

    reason: String,

    /// A set of status of sub steps of the total behavior.
    sub: HashMap<String, BehaviorStatus>,
}

struct BehaviorReport {
    evaluations: Vec<BehaviorEvaluation>,
}

/// A collection of [BehaviorEvaluation]s
impl BehaviorReport {
    pub fn new() -> Self { BehaviorReport { evaluations: vec![] } }

    /// Add another evaluation to the report.
    pub fn add(&mut self, evaluation: BehaviorEvaluation) { self.evaluations.push(evaluation); }
}
