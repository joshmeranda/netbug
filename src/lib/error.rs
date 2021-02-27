use pcap;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;

#[derive(Debug)]
pub enum ClientError {
    Io(io::Error),
    Pcap(pcap::Error),
}

impl Display for ClientError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Io(err) => write!(f, "System io error: {}", err.to_string()),
            ClientError::Pcap(err) => write!(f, "Pcap Error: {}", err.to_string()),
        }
    }
}

impl Error for ClientError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ClientError::Io(err) => Some(err),
            ClientError::Pcap(err) => Some(err),
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(err: io::Error) -> Self {
        ClientError::Io(err)
    }
}

impl From<pcap::Error> for ClientError {
    fn from(err: pcap::Error) -> Self {
        ClientError::Pcap(err)
    }
}
