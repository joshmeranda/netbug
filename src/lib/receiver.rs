use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;

use crate::error::{NbugError, Result};
use crate::{BUFFER_SIZE, HEADER_LENGTH};

pub struct Receiver {
    listener: TcpListener,

    pcap_dir: PathBuf,
}

impl Receiver {
    /// Construct a new [Receiver] from a [TcpListener] and a [PathBuf] to the
    /// root pcap directory.
    pub fn new(listener: TcpListener, pcap_dir: PathBuf) -> Receiver { Receiver { listener, pcap_dir } }

    /// Receive a pcap from a client and return the file the data was dumped to.
    /// The receiver blocks until either a pcap is receiver from the client, or
    /// an error occurs.
    pub fn receive(&mut self) -> Result<Vec<PathBuf>> {
        let (stream, peer) = self.listener.accept()?;

        // ensure that a pcap directory for the peer exists
        let mut dir = self.pcap_dir.clone();
        dir.push(peer.ip().to_string());

        if !dir.exists() {
            fs::create_dir_all(&dir)?;
        }

        let mut received = vec![];
        let mut reader = BufReader::with_capacity(BUFFER_SIZE, stream);

        while let Ok(path) = self.receive_pcap(&mut reader, dir.clone()) {
            received.push(path);
        }

        Ok(received)
    }

    fn receive_pcap(&self, stream: &mut BufReader<TcpStream>, dir: PathBuf) -> Result<PathBuf> {
        let mut header_buffer = [0; HEADER_LENGTH];

        stream.read_exact(&mut header_buffer)?;

        // pull out header values
        let _version: u8 = header_buffer[0]; // for now version can be safely ignored since there is only one version
        let name_len = header_buffer[1] as usize;
        let data_len = u64::from_be_bytes(header_buffer[2..HEADER_LENGTH].try_into().unwrap()) as usize;

        let mut buffer = [0; BUFFER_SIZE];
        stream.read_exact(&mut buffer[0..name_len])?;

        let name = match std::str::from_utf8(&buffer[0..name_len]) {
            Ok(n) => n,
            Err(_) => return Err(NbugError::Packet(String::from("Capture file name is not valid utf8"))),
        };

        let mut pcap_path = dir;
        pcap_path.push(format!("{}.pcap", name));
        let pcap_file = File::create(&pcap_path)?;

        let mut writer = BufWriter::new(pcap_file);

        // the amount of byte left to be added to the raw_message Vec after the initial
        // chunk
        let mut remaining_bytes = data_len;

        // pull out the remaining data
        while remaining_bytes > 0 {
            let upper = if remaining_bytes >= BUFFER_SIZE {
                BUFFER_SIZE
            } else {
                remaining_bytes
            };
            let slice = &mut buffer[0..upper];

            stream.read_exact(slice)?;
            writer.write_all(slice)?;

            remaining_bytes -= upper;
        }

        Ok(pcap_path)
    }
}
