use std::net::{Shutdown, SocketAddr, TcpStream, UdpSocket, IpAddr};
use std::process::Command;
use std::str::FromStr;
use std::time::Duration;

use crate::error::Result;
use crate::protocols::ProtocolPacketHeader;

#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum BehaviorProtocol {
    Icmp,
    Icmpv6,

    Tcp,
    Udp,
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
#[derive(Deserialize)]
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
#[derive(Deserialize)]
pub struct Behavior {
    src: Option<String>,

    dst: String,

    #[serde(rename = "protocol")]
    protocol: BehaviorProtocol,

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
            BehaviorProtocol::Icmp => {
                let mut handle = Command::new("ping").args(&["-c", "1", &self.dst]).spawn()?;
                handle.wait()?;
            },
            BehaviorProtocol::Icmpv6 => {
                let mut handle = Command::new("ping").args(&["-6", "-c", "1", &self.dst]).spawn()?;
                handle.wait()?;
            },
            BehaviorProtocol::Tcp => {
                let addr = SocketAddr::from_str(self.dst.as_str())?;
                let sock = TcpStream::connect_timeout(&addr, timeout).unwrap();

                sock.shutdown(Shutdown::Both)?;
            },
            BehaviorProtocol::Udp => {
                let addr = SocketAddr::from_str(self.dst.as_str())?;
                let socket = UdpSocket::bind(&addr).unwrap();

                socket.send(&[])?;
            },
        };

        Ok(())
    }

    /// Determine if a list off packet headers satisfies the expected behavior.
    pub fn passed<'a>(&self, _headers: Vec<&'a dyn ProtocolPacketHeader>) {
        todo!()
    }
}
