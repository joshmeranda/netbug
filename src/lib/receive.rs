use std::convert::TryInto;
use std::fs;
use std::fs::File;
use std::io::{BufReader, BufWriter, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc::Sender;

use crate::error::{NbugError, Result};
use crate::{BUFFER_SIZE, HEADER_LENGTH};

/// Listen for new connections and receive pcaps from those connections. The
/// resulting pcap [`Path`] is sent through the `sender` channel, and should be
/// consumed by another task or by the caller.
pub async fn receive(listener: TcpListener, pcap_dir: PathBuf, sender: Sender<PathBuf>, interrupt_received: Arc<AtomicBool>) -> Result<()> {
    while ! interrupt_received.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, peer)) => {
                // ensure that a pcap directory for the peer exists
                let mut dir = pcap_dir.join(peer.ip().to_string());

                if !dir.exists() {
                    fs::create_dir_all(&dir)?;
                }

                let mut reader = BufReader::with_capacity(BUFFER_SIZE, stream);

                while let Ok(path) = receive_pcap(&mut reader, dir.clone()) {
                    (&sender).send(path).await;
                }
            },
            Err(err) => if err.kind() == ErrorKind::WouldBlock {
                /* do nothing */
            } else {
                eprintln!("error establishing a new peer connection: {}", err);
            }
        }
    }

    Ok(())
}

/// Receive a single pcap from the given [`TcpStream`] and return the
/// [`PathBuf`] to the created pcap file.
fn receive_pcap(stream: &mut BufReader<TcpStream>, dir: PathBuf) -> Result<PathBuf> {
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

/*pub struct Receiver {
    listener: TcpListener,

    pcap_dir: PathBuf,
}

impl Receiver {
    /// Construct a new [Receiver] from a [TcpListener] and a [PathBuf] to the
    /// root pcap directory.
    pub fn new(listener: TcpListener, pcap_dir: PathBuf) -> Receiver {
        Receiver {
            listener,
            pcap_dir
        }
    }

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
}*/
