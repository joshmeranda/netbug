use std::fmt::{self, Display, Formatter};
use std::net::AddrParseError;
use std::{error, io};

use toml::de;

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Toml(de::Error),
    Addr(AddrParseError),
    Other(String),
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(err) => {
                write!(f, "Error reading configuration file: {}", err)
            },
            ConfigError::Toml(err) => write!(f, "Error parsing configuration: {}", err),
            ConfigError::Addr(err) => write!(f, "Bad address: {}", err),
            ConfigError::Other(s) => write!(f, "{}", s),
        }
    }
}

impl error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ConfigError::Io(err) => Some(err),
            ConfigError::Toml(err) => Some(err),
            ConfigError::Addr(err) => Some(err),
            ConfigError::Other(_) => None,
        }
    }
}

impl From<io::Error> for ConfigError {
    fn from(err: io::Error) -> Self { ConfigError::Io(err) }
}

impl From<de::Error> for ConfigError {
    fn from(err: de::Error) -> Self { ConfigError::Toml(err) }
}

impl From<AddrParseError> for ConfigError {
    fn from(err: AddrParseError) -> Self { ConfigError::Addr(err) }
}
