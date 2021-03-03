use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::result;

use crate::config::defaults;
use crate::config::server::ServerConfig;
use crate::error::NbugError;

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
        let listener = TcpListener::bind(self.srv_addr)?;

        for stream in listener.incoming() {
            let clone = self.pcap_dir.clone();

            std::thread::spawn(|| Server::receive_pcap(stream.unwrap(), clone));
        }

        Ok(())
    }

    /// Handler for a tcp connection which will receive and dump a pcap file from a client.
    fn receive_pcap(mut stream: TcpStream, _pcap_dir: PathBuf) {
        loop {
            // todo: receive and create pcap file to local server
            let mut s = String::new();

            let n = stream
                .read_to_string(&mut s)
                .expect("could could not read from stream");

            if n == 0 {
                break;
            }
        }
    }
}
