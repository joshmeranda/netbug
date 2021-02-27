use std::error::Error;

use std::io;
use toml::de;
use std::fmt::{self, Display, Formatter};

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Toml(de::Error),
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(err) => write!(f, "Error reading configuration file: {}", err.to_string()),
            ConfigError::Toml(err) => write!(f, "Error parsing configuration: {}", err.to_string())
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ConfigError::Io(err) => Some(err),
            ConfigError::Toml(err) => Some(err)
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
