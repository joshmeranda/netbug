use std::convert::Into;
use std::convert::TryFrom;
use std::fs;
use std::path::Path;
use std::result;
use std::str;

use crypto::digest::Digest;
use crypto::sha3::Sha3;

use crate::error::NbugError;

type Result = result::Result<PcapMessage, NbugError>;

/// Struct representing network packet containing all or part of a client generated pcap file. Note
/// the actual packet sent over the wire will likely have extra fields not defined here explicitly
/// such as the checksum.
///
/// todo: implement a better checksum / hashing method
pub struct PcapMessage {
    /// The version of the message. This will allow for providing backwards compatibility when using
    /// an older client with a newer server which may have an updated message structure.
    version: u8,

    /// The capture name.
    name: String,

    /// The capture data.
    data: Vec<u8>,
}

impl PcapMessage {
    const MESSAGE_VERSION: u8 = 0;

    pub fn from_pcap<P: AsRef<Path>>(path: P) -> Result {
        let name: String = String::from(path.as_ref().file_name().unwrap().to_str().unwrap());
        let data: Vec<u8> = fs::read(path).unwrap();

        Ok(PcapMessage {
            version: PcapMessage::MESSAGE_VERSION,
            name,
            data,
        })
    }

    pub fn dump_pcap(&self) {
        todo!("Dump pcap data to local file");
    }

    fn _generate_checksum(data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha3::sha3_256();
        let mut cksum = Vec::<u8>::with_capacity(hasher.output_bytes());

        hasher.input(data);
        hasher.result(cksum.as_mut_slice());

        cksum
    }
}

// todo: perform safety checks that the data the goes on the wire can be read back from the wire
//   the name of the network device is u8::MAX characters or less

/// Try constructing a [PcapMessage] from raw byte data.
///
/// todo: use cleaner indexing of data
/// todo: implement checksum / data verification
impl TryFrom<Vec<u8>> for PcapMessage {
    type Error = NbugError;

    fn try_from(bytes: Vec<u8>) -> result::Result<Self, Self::Error> {
        let name_len: usize = bytes[1] as usize;
        let data_len: usize = bytes[2] as usize;

        let name = str::from_utf8(&bytes[3..name_len + 3]).unwrap();

        let data = &bytes[name_len + 3..name_len + data_len + 3];

        Ok(PcapMessage {
            version: PcapMessage::MESSAGE_VERSION,
            name: String::from(name),
            data: Vec::from(data),
            // _casper: std::marker::PhantomData,
        })
    }
}

/// Create the raw packet data from the PcapMessage.
impl Into<Vec<u8>> for PcapMessage {
    fn into(mut self) -> Vec<u8> {
        let mut bytes: Vec<u8> = vec![];

        // message "headerr"
        bytes.push(self.version);
        bytes.push(self.name.len() as u8);
        bytes.push(self.data.len() as u8);

        // message body
        unsafe {
            bytes.append(self.name.as_mut_vec());
        }
        bytes.append(&mut self.data);

        bytes
    }
}
