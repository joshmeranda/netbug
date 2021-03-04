use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::result;

use crate::config::defaults;
use crate::config::server::ServerConfig;
use crate::error::NbugError;
use crate::message::PcapMessage;
use std::convert::TryFrom;

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
    const BUFFER_SIZE: usize = 5;

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
        let listener = TcpListener::bind(self.srv_addr)?;

        println!("Server is listening...");

        for stream in listener.incoming() {
            let _clone = self.pcap_dir.clone();

            std::thread::spawn(|| match Server::receive_pcap(stream.unwrap()) {
                Ok(pcap) => pcap.dump_pcap(),
                Err(err) => eprintln!("Server Error: {}", err.to_string()),
            });
        }

        Ok(())
    }

    /// Handler for a tcp connection which will receive and dump a pcap file from a client.
    fn receive_pcap(mut stream: TcpStream) -> result::Result<PcapMessage, NbugError> {
        // todo: receive and create pcap file to local server
        // let mut buffer = Vec::<u8>::with_capacity(Server::BUFFER_SIZE);
        let mut buffer = [0; Server::BUFFER_SIZE];
        let mut raw_message = Vec::<u8>::new();

        let mut byte_count: usize = 0;

        // block until at least the message header is retrieved
        while byte_count < 3 {
            // check that at least the message header has been received
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
        let data_len: u8 = buffer[2];

        // the amount of byte left to be added to the raw_message Vec
        let mut remaining_bytes: usize = (name_len + data_len + 3) as usize;

        // pull out the data
        while remaining_bytes > 0 {
            if byte_count <= remaining_bytes {
                remaining_bytes -= raw_message.write(&buffer[0..byte_count])?;
                byte_count = stream.read(&mut buffer)?;
            } else {
                // todo: client is sending two messages one after another
            }
        }
        // todo: handle a closed stream
        Ok(PcapMessage::try_from(raw_message).unwrap())
    }
}
