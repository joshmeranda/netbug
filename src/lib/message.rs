use std::convert::TryFrom;
use std::convert::{Into, TryInto};
use std::fs;
use std::path::Path;
use std::result;
use std::str;

use crypto::digest::Digest;
use crypto::sha3::Sha3;

use crate::config::error::Error;
use crate::error::NbugError;
use crate::MESSAGE_VERSION;

type Result = result::Result<PcapMessage, NbugError>;

/// Struct representing network packet containing all or part of a client generated pcap file. Note
/// the actual packet sent over the wire will likely have extra fields not defined here explicitly
/// such as the data length.
///
/// todo: implement a better checksum / hashing method
pub struct PcapMessage {
    /// The version of the message. This will allow for providing backwards compatibility when using
    /// an older client with a newer server which may have an updated message structure.
    version: u8,

    /// The name of the capture interface.
    name: String,
}

impl PcapMessage {
    pub fn from_pcap<P: AsRef<Path>>(path: P) -> Result {
        let name: String = String::from(path.as_ref().file_name().unwrap().to_str().unwrap());

        Ok(PcapMessage {
            version: MESSAGE_VERSION,
            name,
        })
    }

    fn _generate_checksum(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3::sha3_256();
        let mut cksum = Vec::<u8>::with_capacity(hasher.output_bytes());

        hasher.input(data);
        hasher.result(cksum.as_mut_slice());

        cksum
    }
}
