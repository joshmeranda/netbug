#![feature(thread_spawn_unchecked)]

pub mod behavior;
pub mod client;
pub mod config;
pub mod error;
pub mod message;
pub mod protocols;
pub mod server;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate num_derive;

use std::fmt;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;

use serde::de::{MapAccess, Visitor};
use serde::{de, Deserialize, Deserializer};

use crate::config::error::ConfigError;
use crate::error::NbugError;

/// The total length og the PcapMessage header as raw bytes. The header is
/// composed of the packet version number (u8), pcap name length (u8), and the
/// total data length (u64).s
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
#[derive(Debug, Deserialize, PartialEq, Eq, Hash)]
enum Addr {
    /// An internet address with only an ip.
    Internet(IpAddr),

    /// A socket address with an ip and port number.
    Socket(SocketAddr),
}

impl FromStr for Addr {
    type Err = NbugError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SocketAddr::from_str(s).map(Addr::Socket).or_else(move |_| {
            IpAddr::from_str(s)
                .map(Addr::Internet)
                .or_else(move |err| Err(NbugError::Config(ConfigError::Addr(err))))
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
