use std::convert::{TryFrom, TryInto};
use std::default;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::Builder;

use pcap::Capture;
use threadpool::ThreadPool;

use crate::behavior::collector::BehaviorCollector;
use crate::behavior::evaluate::BehaviorReport;
use crate::behavior::Behavior;
use crate::config::defaults;
use crate::config::server::ServerConfig;
use crate::error::{NbugError, Result};
use crate::protocols::ethernet::IeeEthernetPacket;
use crate::protocols::icmp::icmpv4::Icmpv4Packet;
use crate::protocols::icmp::icmpv6::Icmpv6Packet;
use crate::protocols::ip::IpPacket;
use crate::protocols::tcp::TcpPacket;
use crate::protocols::udp::UdpPacket;
use crate::protocols::{ProtocolNumber, ProtocolPacket};
use crate::{Addr, BUFFER_SIZE, HEADER_LENGTH};

pub struct Server {
    addr: SocketAddr,

    n_workers: usize,

    running: Arc<AtomicBool>,

    pcap_dir: PathBuf,
}

impl Default for Server {
    fn default() -> Server {
        Server {
            addr:      SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), defaults::default_server_port()),
            n_workers: defaults::server::default_n_workers(),
            running:   Arc::new(AtomicBool::new(false)),
            pcap_dir:  defaults::default_pcap_dir(),
        }
    }
}

impl Server {
    pub fn new(addr: SocketAddr, n_workers: usize, pcap_dir: PathBuf) -> Server {
        Server {
            addr,
            n_workers,
            pcap_dir,
            ..Server::default()
        }
    }

    /// Start the netbug server and begin listening for tcp connections.
    pub fn start(&self) -> Result<()> {
        let builder = Builder::new().name(String::from("nbug_server"));

        let running_flag = Arc::clone(&self.running);
        let srv_addr = self.addr.clone();
        let pcap_dir = self.pcap_dir.clone();

        running_flag.store(true, Ordering::SeqCst);

        // unsafe to allow  the thread to run anywhere the struct is valid.
        unsafe {
            builder.spawn_unchecked(move || {
                if let Err(err) = Server::handle_connections(&running_flag, srv_addr, pcap_dir) {
                    eprintln!("{}", err.to_string());
                }

                // once connections are not being handled stop the server
                running_flag.store(false, Ordering::SeqCst);
            })?;
        }

        Ok(())
    }

    /// Handle accepting client connections.
    fn handle_connections(running_flag: &Arc<AtomicBool>, srv_addr: SocketAddr, pcap_dir: PathBuf) -> Result<()> {
        // todo: implement a clean shutdown (catch interrupts)
        let listener = TcpListener::bind(srv_addr)?;

        println!("Bound server to '{}'", listener.local_addr().unwrap().to_string());

        // todo: make map of thread id to handle?
        //   currently handle vector will keep building until server is shutdown
        let pool = ThreadPool::new(4);

        // todo: consider polling for better performance
        while running_flag.load(Ordering::SeqCst) {
            let (stream, addr) = match listener.accept() {
                Ok((stream, addr)) => (stream, addr),
                Err(_) => continue,
            };

            println!("Accepted connection from '{}'", addr.to_string());

            // todo: support hostname rather than raw ip which can change
            let mut pcap_dir = pcap_dir.clone();
            pcap_dir.push(addr.to_string());

            // ensure the host pcap directory exists
            if !pcap_dir.exists() {
                if let Err(err) = fs::create_dir_all(&pcap_dir) {
                    eprintln!("Error creating pcap directory: {}", err.to_string());
                };
            }

            pool.execute(|| match Server::receive_pcap(stream, pcap_dir) {
                Ok(_) => println!("Received pcaps"),
                Err(err) => eprintln!("Server Error: {}", err.to_string()),
            });
        }

        pool.join();

        Ok(())
    }

    /// Stop a running server, if the server is not running, Err is returned.
    pub fn stop(&self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            self.running.store(true, Ordering::SeqCst);

            Ok(())
        } else {
            Err(NbugError::Server(String::from("Server not running")))
        }
    }

    /// Check if the server is running.
    pub fn is_running(&self) -> bool { self.running.load(Ordering::SeqCst) }

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
}
