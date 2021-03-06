use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::result;

use crate::config::defaults;
use crate::config::server::ServerConfig;
use crate::error::NbugError;
use crate::message::PcapMessage;
use crate::{BUFFER_SIZE, HEADER_LENGTH};
use std::convert::{TryFrom, TryInto};

type Result = result::Result<(), NbugError>;

pub struct Server {
    pcap_dir: PathBuf,

    srv_addr: SocketAddr,
}

impl Default for Server {
    fn default() -> Server {
        Server {
            pcap_dir: defaults::default_pcap_dir(),
            srv_addr: SocketAddr::new(
                IpAddr::from(Ipv4Addr::LOCALHOST),
                defaults::default_server_port(),
            ),
        }
    }
}

impl Server {

    pub fn new() -> Server {
        Server::default()
    }

    /// Construct a server from a [ServerConfig] which is consumed.
    pub fn from_config(cfg: ServerConfig) -> Server {
        Server {
            pcap_dir: cfg.pcap_dir,
            srv_addr: cfg.srv_addr,
            ..Server::default()
        }
    }

    /// Start the netbug server and begin listening for tcp connections.
    pub fn start(&self) -> Result {
        // make sure the target pcap directory exists
        if !self.pcap_dir.exists() {
            fs::create_dir_all(&self.pcap_dir)?;
        }

        let listener = TcpListener::bind(self.srv_addr)?;
        let mut handles = vec![];

        for stream in listener.incoming() {
            // todo: create subdirectory for each new host (use TcpListener::accept in loop)
            //   will need to ensure each host directory exists before continuing to receiving the
            //   pcap
            let mut pcap_dir = self.pcap_dir.clone();

            handles.push(std::thread::spawn(|| {
                match Server::receive_pcap(stream.unwrap(), pcap_dir) {
                    Ok(pcap) => println!("Received pcaps"),
                    Err(err) => eprintln!("Server Error: {}", err.to_string()),
                }
            }));
        }

        for handle in handles {
            handle.join();
        }

        Ok(())
    }

    /// Handler for a tcp connection which will receive and dump a pcap file from a client. This
    /// method assumes that pcap_dir is valid directory, and will throw an error if it is not.
    fn receive_pcap<P: AsRef<Path>>(mut stream: TcpStream, pcap_dir: P) -> Result {
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

        let name =
            match std::str::from_utf8(&buffer[HEADER_LENGTH..HEADER_LENGTH + name_len as usize]) {
                Ok(n) => n,
                Err(_) => {
                    return Err(NbugError::Packet(String::from(
                        "Packet name is not valid utf8",
                    )))
                }
            };

        let mut pcap_path = pcap_dir.as_ref().to_path_buf();
        pcap_path.push(format!("{}.pcap", name));
        let mut pcap_file = File::create(pcap_path)?;

        // the amount of byte left to be added to the raw_message Vec after the initial chunk
        let mut remaining_bytes: usize = data_len as usize;

        // read data data after header to file
        remaining_bytes -=
            pcap_file.write(&buffer[HEADER_LENGTH + name_len as usize..byte_count])?;

        // pull out the remaining data
        while remaining_bytes > 0 {
            byte_count = stream.read(&mut buffer)?;

            if byte_count == 0 {
                return Err(NbugError::Server(String::from(
                    "Client unexpectedly closed connection",
                )));
            }

            remaining_bytes -= byte_count;

            pcap_file.write(&buffer[0..byte_count]);
        }

        Ok(())
    }
}
