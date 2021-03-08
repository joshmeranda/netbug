use std::fmt::{self, Display, Formatter};
use std::{error, io};

use toml::de;
use std::net::AddrParseError;

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Toml(de::Error),
    Addr(AddrParseError),
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(err) => write!(f, "Error reading configuration file: {}", err.to_string()),
            ConfigError::Toml(err) => write!(f, "Error parsing configuration: {}", err.to_string()),
            ConfigError::Addr(err) => write!(f, "Bad address: {}", err.to_string()),
        }
    }
}

impl error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            ConfigError::Io(err) => Some(err),
            ConfigError::Toml(err) => Some(err),
            ConfigError::Addr(err) => Some(err)
        }
    }
}

impl From<io::Error> for ConfigError {
    fn from(err: io::Error) -> Self {
        ConfigError::Io(err)
    }
}

impl From<de::Error> for ConfigError {
    fn from(err: de::Error) -> Self {
        ConfigError::Toml(err)
    }
}

impl From<AddrParseError> for ConfigError {
    fn from(err: AddrParseError) -> Self {
        ConfigError::Addr(err)
    }
}