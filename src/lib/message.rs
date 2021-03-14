use std::path::{Path, PathBuf};

use crypto::digest::Digest;
use crypto::sha3::Sha3;

use crate::error::Result;
use crate::MESSAGE_VERSION;

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

    pcap_path: PathBuf,
}

impl PcapMessage {
    pub fn from_pcap<P: AsRef<Path>>(path: P) -> Result<PcapMessage> {
        let name: String = String::from(path.as_ref().file_name().unwrap().to_str().unwrap());

        Ok(PcapMessage {
            version: MESSAGE_VERSION,
            name,
            pcap_path: path.as_ref().to_path_buf(),
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
