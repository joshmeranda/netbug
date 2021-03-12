use pcap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;
use std::net::AddrParseError;

use super::config::error::ConfigError;

pub type Result<T> = std::result::Result<T, NbugError>;

#[derive(Debug)]
pub enum NbugError {
    Client(String),
    Server(String),
    Io(io::Error),
    Config(ConfigError),
    Pcap(pcap::Error),
    Packet(String),
}

impl Display for NbugError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            NbugError::Client(msg) => write!(f, "Client error: {}", msg),
            NbugError::Server(msg) => write!(f, "Server error: {}", msg),
            NbugError::Io(err) => write!(f, "System io error: {}", err.to_string()),
            NbugError::Config(err) => write!(f, "{}", err.to_string()),
            NbugError::Pcap(err) => write!(f, "Pcap Error: {}", err.to_string()),
            NbugError::Packet(msg) => write!(f, "Client error: {}", msg),
        }
    }
}

impl Error for NbugError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            NbugError::Client(_) => None,
            NbugError::Server(_) => None,
            NbugError::Io(err) => Some(err),
            NbugError::Config(err) => Some(err),
            NbugError::Pcap(err) => Some(err),
            NbugError::Packet(_) => None,
        }
    }
}

impl From<io::Error> for NbugError {
    fn from(err: io::Error) -> Self {
        NbugError::Io(err)
    }
}

impl From<pcap::Error> for NbugError {
    fn from(err: pcap::Error) -> Self {
        NbugError::Pcap(err)
    }
}

impl From<AddrParseError> for NbugError {
    fn from(err: AddrParseError) -> Self {
        NbugError::Config(ConfigError::Addr(err))
    }
}