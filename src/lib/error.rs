use pcap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;

#[derive(Debug)]
pub enum NbugError {
    Client(String),
    Io(io::Error),
    Pcap(pcap::Error),
    Packet(String),
}

impl Display for NbugError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            NbugError::Client(msg) => write!(f, "Client error: {}", msg),
            NbugError::Io(err) => write!(f, "System io error: {}", err.to_string()),
            NbugError::Pcap(err) => write!(f, "Pcap Error: {}", err.to_string()),
            NbugError::Packet(msg) => write!(f, "Client error: {}", msg),
        }
    }
}

impl Error for NbugError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            NbugError::Client(_) => None,
            NbugError::Io(err) => Some(err),
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
