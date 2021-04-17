use std::convert::{TryFrom, TryInto};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};

use pcap::Capture;

use crate::behavior::{Behavior, BehaviorCollector};
use crate::config::defaults;
use crate::config::server::ServerConfig;
use crate::error::{NbugError, Result};
use crate::protocols::ethernet::IeeEthernetPacket;
use crate::protocols::icmp::icmpv4::Icmpv4Packet;
use crate::protocols::icmp::icmpv6::Icmpv6Packet;
use crate::protocols::ip::IpPacket;
use crate::protocols::tcp::TcpPacket;
use crate::protocols::udp::UdpPacket;
use crate::protocols::{ProtocolNumber, ProtocolPacketHeader};
use crate::{Addr, BUFFER_SIZE, HEADER_LENGTH};

pub struct Server {
    pcap_dir: PathBuf,

    srv_addr: SocketAddr,

    behaviors: Vec<Behavior>,
}

impl Default for Server {
    fn default() -> Server {
        Server {
            pcap_dir:  defaults::default_pcap_dir(),
            srv_addr:  SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), defaults::default_server_port()),
            behaviors: Vec::<Behavior>::new(),
        }
    }
}

impl Server {
    pub fn new() -> Server { Server::default() }

    /// Construct a server from a [ServerConfig] which is consumed.
    pub fn from_config(cfg: ServerConfig) -> Server {
        Server {
            pcap_dir: cfg.pcap_dir,
            srv_addr: cfg.srv_addr,
            behaviors: cfg.behaviors,
            ..Server::default()
        }
    }

    /// Start the netbug server and begin listening for tcp connections.
    pub fn start(&self) -> Result<()> {
        // todo: implement a clean shutdown (catch interrupts)
        let listener = TcpListener::bind(self.srv_addr)?;
        let mut handles = vec![];

        loop {
            let (stream, addr) = match listener.accept() {
                Ok((s, a)) => (s, a),
                Err(err) => {
                    eprintln!("Error accepting connection: {}", err.to_string());
                    continue;
                },
            };

            // todo: support hostname rather than raw ip which can change
            let mut pcap_dir = self.pcap_dir.clone();
            pcap_dir.push(addr.ip().to_string());

            // ensure the host pcap directory exists
            if !pcap_dir.exists() {
                if let Err(err) = fs::create_dir_all(&pcap_dir) {
                    eprintln!("Error creating pcap directory: {}", err.to_string());
                };
            }

            handles.push(std::thread::spawn(|| match Server::receive_pcap(stream, pcap_dir) {
                Ok(_) => println!("Received pcaps"),
                Err(err) => eprintln!("Server Error: {}", err.to_string()),
            }));

            self.process();
        }
    }

    /// Handler for a tcp connection which will receive and dump a pcap file
    /// from a client. This method assumes that pcap_dir is valid directory,
    /// and will throw an error if it is not.
    fn receive_pcap<P: AsRef<Path>>(mut stream: TcpStream, pcap_dir: P) -> Result<()> {
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

        let mut pcap_path = pcap_dir.as_ref().to_path_buf();
        pcap_path.push(format!("{}.pcap", name));
        let mut pcap_file = File::create(pcap_path)?;

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

        Ok(())
    }

    /// Iterate over server capture directory. This method will traverse only
    /// the children of the root pcap directory, and so any non-directory files
    /// in the root pcap directory will be ignored.
    pub fn process(&self) -> Result<()> {
        let mut collector = BehaviorCollector::new();

        for behavior in &self.behaviors {
            collector.insert_behavior(&behavior);
        }

        for entry in fs::read_dir(&self.pcap_dir)? {
            let child = match entry {
                Ok(entry) => entry,
                Err(_) => continue,
            };

            let file_type = match child.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };

            if file_type.is_dir() {
                for sub_entry in fs::read_dir(child.path())? {
                    let path = match sub_entry {
                        Ok(sub_entry) => sub_entry.path(),
                        Err(_) => continue,
                    };

                    match self.process_pcap(&path, &mut collector) {
                        Ok(_) => {},
                        Err(err) => eprintln!(
                            "Error processing pcap '{}': {}",
                            path.to_str().unwrap(),
                            err.to_string()
                        ),
                    }
                }
            }
        }

        Ok(())
    }

    /// Process a single pcap file, by adding the found [ProtocolPacketHeaders
    /// into the given [BehaviorCollector].
    fn process_pcap(&self, path: &PathBuf, collector: &mut BehaviorCollector) -> Result<()> {
        let mut capture = Capture::from_file(path)?;

        while let Ok(packet) = capture.next() {
            let ethernet = IeeEthernetPacket::try_from(packet.data)?;

            let mut offset: usize = ethernet.header_length();
            let ip = IpPacket::try_from(&packet.data[offset..])?;

            offset += ip.header_length();

            let protocol = match &ip {
                IpPacket::V4(packet) => packet.protocol,
                IpPacket::V6(packet) => packet.next_header,
            };

            let packet_header: Option<Box<dyn ProtocolPacketHeader>> = match protocol {
                ProtocolNumber::Icmp => match Icmpv4Packet::try_from(&packet.data[offset..]) {
                    Ok(packet) => Some(Box::new(packet)),
                    Err(err) => {
                        eprintln!("Error parsing icmp packet: {}", err.to_string());
                        None
                    },
                },
                ProtocolNumber::Ipv6Icmp => match Icmpv6Packet::try_from(&packet.data[offset..]) {
                    Ok(packet) => Some(Box::new(packet)),
                    Err(err) => {
                        eprintln!("Error parsing icmpv6 packet: {}", err.to_string());
                        None
                    },
                },
                ProtocolNumber::Tcp => match TcpPacket::try_from(&packet.data[offset..]) {
                    Ok(packet) => Some(Box::new(packet)),
                    Err(err) => {
                        eprintln!("Error parsing icmpv6 packet: {}", err.to_string());
                        None
                    },
                },
                ProtocolNumber::Udp => match UdpPacket::try_from(&packet.data[offset..]) {
                    Ok(packet) => Some(Box::new(packet)),
                    Err(err) => {
                        eprintln!("Error parsing icmp packet: {}", err.to_string());
                        None
                    },
                },
                _ => {
                    println!("else: {}", ip.protocol_type() as u8);
                    None
                },
            };

            if let Some(header) = packet_header {
                let src = Some(Addr::Internet(ip.source()));
                let dst = Addr::Internet(ip.destination());

                if let Err(err) = collector.insert_header(header, src, dst) {
                    eprintln!("{}", err.to_string());
                }
            }
        }

        Ok(())
    }
}
