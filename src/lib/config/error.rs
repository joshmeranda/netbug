use std::fmt::{self, Display, Formatter};
use std::{error, io};

use toml::de;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Toml(de::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(err) => {
                write!(f, "Error reading configuration file: {}", err.to_string())
            }
            Error::Toml(err) => write!(f, "Error parsing configuration: {}", err.to_string()),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            Error::Toml(err) => Some(err),
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Error::Io(err)
    }
}

impl From<de::Error> for Error {
    fn from(err: de::Error) -> Self {
        Error::Toml(err)
    }
}
