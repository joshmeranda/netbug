pub mod behavior;
pub mod bpf;
pub mod client;
pub mod config;
pub mod error;
pub mod process;
pub mod protocols;
pub mod receive;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate num_derive;

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use serde::{Serialize, Serializer};

use crate::config::error::ConfigError;
use crate::error::NbugError;

/// The total length og the PcapMessage header as raw bytes. The header is
/// composed of the packet version number (u8), pcap name length (u8), and the
/// total data length (u64).
pub const HEADER_LENGTH: usize = 10;

/// This buffer size must be large enough to contain at least the header
/// [HEADER_LENGTH] and interface file name which on most systems should be 16
/// byte including the null byte.
const BUFFER_SIZE: usize = 1024;

/// The current message protocol version, will allow future iterations of the
/// netbug server to be backwards compatible with stale clients.
const MESSAGE_VERSION: u8 = 0;

/// Simple wrapper around address types allowing for multiple address
/// specifications.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Addr {
    /// An internet address with only an ip.
    Internet(IpAddr),

    /// A socket address with an ip and port number.
    Socket(SocketAddr),
}

impl Addr {
    pub fn ip(&self) -> IpAddr {
        match self {
            Addr::Internet(ip) => *ip,
            Addr::Socket(socket) => socket.ip(),
        }
    }

    pub fn port(&self) -> Option<u16> {
        match self {
            Addr::Internet(_) => None,
            Addr::Socket(socket) => Some(socket.port()),
        }
    }
}

impl FromStr for Addr {
    type Err = NbugError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SocketAddr::from_str(s).map(Addr::Socket).or_else(move |_| {
            IpAddr::from_str(s)
                .map(Addr::Internet)
                .map_err(move |err| NbugError::Config(ConfigError::Addr(err)))
        })
    }
}

impl ToString for Addr {
    fn to_string(&self) -> String {
        match self {
            Addr::Internet(addr) => addr.to_string(),
            Addr::Socket(addr) => addr.to_string(),
        }
    }
}

impl<'de> serde::Deserialize<'de> for Addr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>, {
        struct AddrVisitor;

        impl<'de> serde::de::Visitor<'de> for AddrVisitor {
            type Value = Addr;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a string from which an Addr could be parsed")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Addr, E> {
                if let Ok(addr) = Addr::from_str(s) {
                    Ok(addr)
                } else {
                    Err(E::invalid_value(serde::de::Unexpected::Str(s), &self))
                }
            }
        }

        deserializer.deserialize_any(AddrVisitor)
    }
}

impl Serialize for Addr {
    fn serialize<S>(&self, serializer: S) -> Result<<S as Serializer>::Ok, <S as Serializer>::Error>
    where
        S: Serializer, {
        serializer.serialize_str(self.to_string().as_str())
    }
}
