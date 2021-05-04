use std::net::{TcpListener, TcpStream, SocketAddr};
use crate::error::{Result, NbugError};
use std::path::{PathBuf, Path};
use std::fs;
use std::io::{Read, Write};
use std::fs::File;
use std::convert::TryInto;
use crate::{BUFFER_SIZE, HEADER_LENGTH};

pub struct Receiver {
    listener: TcpListener,

    pcap_dir: PathBuf,
}

impl Receiver {
    /// Construct a new [Receiver] from a [SocketAddr] and a [PathBuf] to the  root pcap directory.
    pub fn new(addr: SocketAddr, pcap_dir: PathBuf) -> Result<Receiver> {
        Ok(Receiver {
            listener: TcpListener::bind(addr)?,
            pcap_dir
        })
    }

    /// Receive a pcap from a client and return the file the data was dumped to. The receiver blocks until either a pcap is receiver from the client, or an error occurs.
    pub fn receive(& mut self) -> Result<PathBuf> {
        let (stream, peer) = self.listener.accept()?;

        // ensure that a pcap directory for the peer exists
        let mut dir = self.pcap_dir.clone();
        dir.push(peer.to_string());

        if !dir.exists() {
            fs::create_dir_all(dir);
        }

        self.receive_pcap(stream)
    }

    fn receive_pcap(&self, mut stream: TcpStream) -> Result<PathBuf> {
        // todo: receive and create pcap file to local server
        let mut buffer = [0; BUFFER_SIZE];
        let mut byte_count: usize = stream.peek(&mut buffer)?;

        // wait until a full message header has been read
        while byte_count < HEADER_LENGTH {
            byte_count = stream.peek(&mut buffer)?;

            if byte_count == 0 {
                return Err(NbugError::Server(String::from(
                    "Client unexpectedly closed the connection",
                )));
            }
        }

        byte_count = stream.read(&mut buffer)?;

        // pull out header values
        let _version: u8 = buffer[0]; // for now version can be safely ignored
        let name_len: u8 = buffer[1];

        // pull out the  message data length from the raw bytes
        let data_len: u64 = u64::from_be_bytes(buffer[2..HEADER_LENGTH].try_into().unwrap());

        let name = match std::str::from_utf8(&buffer[HEADER_LENGTH..HEADER_LENGTH + name_len as usize]) {
            Ok(n) => n,
            Err(_) => return Err(NbugError::Packet(String::from("Packet name is not valid utf8"))),
        };

        let mut pcap_path = self.pcap_dir.clone();
        pcap_path.push(stream.peer_addr().unwrap().to_string());
        pcap_path.push(format!("{}.pcap", name));
        let mut pcap_file = File::create(&pcap_path)?;

        // the amount of byte left to be added to the raw_message Vec after the initial
        // chunk
        let mut remaining_bytes: usize = data_len as usize;

        // read data data after header to file
        remaining_bytes -= pcap_file.write(&buffer[HEADER_LENGTH + name_len as usize..byte_count])?;

        // pull out the remaining data
        while remaining_bytes > 0 {
            byte_count = stream.read(&mut buffer)?;

            if byte_count == 0 {
                return Err(NbugError::Server(String::from("Client unexpectedly closed connection")));
            }

            remaining_bytes -= byte_count;

            pcap_file.write(&buffer[0..byte_count])?;
        }

        Ok(pcap_path)
    }
}