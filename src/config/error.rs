use std::error;

use std::io;
use toml::de;

#[derive(Debug)]
pub enum ConfigError {
    Io(io::Error),
    Toml(de::Error),
}

// todo: implement macro for simpler new types
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
