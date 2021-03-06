use std::default::Default;
use std::fs::{self, File};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::result;
use std::sync::{Arc, Mutex};
use std::thread::Builder;

use pcap::{Capture, Device};

use crate::config::client::ClientConfig;
use crate::config::defaults;
use crate::error::NbugError;
use crate::message::PcapMessage;
use crate::{BUFFER_SIZE, HEADER_LENGTH, MESSAGE_VERSION};
use std::io::{Read, Write};

type Result = result::Result<(), NbugError>;

/// The main Netbug client to capture network and dump network traffic to pcap files.
pub struct Client {
    script_dir: PathBuf,

    pcap_dir: PathBuf,

    allow_concurrent: bool,

    devices: Vec<Device>,

    capturing: Arc<Mutex<bool>>,

    srv_addr: SocketAddr,
}

impl Default for Client {
    fn default() -> Client {
        Client {
            script_dir: defaults::default_script_dir(),
            pcap_dir: defaults::default_pcap_dir(),
            allow_concurrent: defaults::client::default_concurrent_run(),
            devices: vec![],
            capturing: Arc::new(Mutex::new(false)),
            srv_addr: SocketAddr::new(
                IpAddr::from(Ipv4Addr::LOCALHOST),
                defaults::default_server_port(),
            ),
        }
    }
}

impl Client {
    pub fn new() -> Client {
        Client::default()
    }

    /// Construct a client from a [ClientConfig] which is consumed.
    pub fn from_config(cfg: ClientConfig) -> Client {
        // find the list of valid devices on which to start a packet capture
        let devices = Device::list().unwrap();
        let devices: Vec<Device> = devices
            .into_iter()
            .filter(|device| cfg.interfaces.contains(&device.name))
            .collect();

        Client {
            script_dir: cfg.script_dir,
            pcap_dir: cfg.pcap_dir,
            allow_concurrent: cfg.allow_concurrent,
            srv_addr: cfg.srv_addr,
            devices,
            ..Client::default()
        }
    }

    /// Run all scripts found in the configured scrip directory and block until all are complete.
    /// todo: consider replacing with Runner struct
    pub fn run_scripts(&self) -> Result {
        let mut children: Vec<Child> = vec![]; // will not always be used

        for entry in self.script_dir.read_dir()? {
            let entry = entry?;
            let path = entry.path();
            let child = Command::new(path.to_str().unwrap()).spawn();

            if let Err(err) = child {
                eprintln!(
                    "Couldn't execute script at '{}': {}",
                    path.to_str().unwrap(),
                    err.to_string()
                );
                break;
            };

            let mut child = child.unwrap();

            // if scripts are allowed to run concurrently add to child Vec, else wait to finish before next iteration
            if self.allow_concurrent {
                children.push(child);
            } else {
                // no need to kill other children since all scripts are run concurrently
                child.wait()?;
            }
        }

        if !children.is_empty() {
            for mut child in children {
                child.wait()?;
            }
        }

        Ok(())
    }

    /// Begin capturing packets on the configured network devices. Note that there is currently no
    /// explicit way to end capture and flush its output, be mindful of your client's scoping to
    /// prevent capturing unnecessary packets.
    pub fn start_capture(&mut self) -> Result {
        if self.is_capturing() {
            return Err(NbugError::Client(String::from(
                "capture is already running",
            )));
        } else if self.devices.is_empty() {
            return Err(NbugError::Client(String::from(
                "no configured network devices",
            )));
        }

        // ensure that the packet capture directory exists
        if !self.pcap_dir.exists() {
            fs::create_dir(self.pcap_dir.clone())?;
        }

        *self.capturing.lock().unwrap() = true;

        for device in &self.devices {
            let capture_flag = Arc::clone(&self.capturing);
            let device_name = String::from(device.name.clone());

            let mut capture = Capture::from_device(device.clone())?
                .timeout(1)
                .open()?
                .setnonblock()?;

            let mut pcap_path = PathBuf::from(&self.pcap_dir);
            pcap_path.push(format!("{}.pcap", &device_name));

            let mut save_file = capture.savefile(pcap_path).unwrap();

            // todo: add timestamp to end of pcap name
            let builder = Builder::new().name(device_name.clone());
            builder.spawn(move || {
                while *capture_flag.lock().unwrap() {
                    match capture.next() {
                        Ok(packet) => save_file.write(&packet),
                        Err(_) => {} // todo: these errors should be handled
                    }
                }

                // force immediate pcap dump
                std::mem::drop(save_file);
            })?;

            println!("Started capture for device '{}'", device_name)
        }

        Ok(())
    }

    /// Signal the client to stop capturing network packets. Note that this simply signals the
    /// capturing thread loops to discontinue iteration rather than immediately stopping them.
    /// Therefore, it is possible for extra packets to be captured and written to the resulting pcap
    /// if the current thread iterations are still in progress.
    pub fn stop_capture(&mut self) -> Result {
        if !self.is_capturing() {
            return Err(NbugError::Client(String::from("no capture is running")));
        }

        *self.capturing.lock().unwrap() = false;
        Ok(())
    }

    pub fn is_capturing(&self) -> bool {
        *self.capturing.lock().unwrap()
    }

    /// Transfer all
    pub fn transfer_all(&self) -> Result {
        for device in &self.devices {
            self.transfer_pcap(device.name.as_str())?;
        }

        Ok(())
    }

    /// Transfer a single pcap to the server.
    pub fn transfer_pcap(&self, interface_name: &str) -> Result {
        let mut tcp = TcpStream::connect(self.srv_addr)?;
        let mut buffer = [u8::default(); BUFFER_SIZE];

        // construct the path to the interface's pcap file
        let mut pcap_path = self.pcap_dir.to_path_buf();
        pcap_path.push(format!("{}.pcap", interface_name));

        let mut pcap_file = File::open(&pcap_path)?;

        // get the amount of bytes in the pcap files
        let mut data_len = fs::metadata(&pcap_path)?.len();
        let mut remaining_bytes = data_len;

        // fill the header bytes with the relevant behavior
        buffer[0] = MESSAGE_VERSION;
        buffer[1] = interface_name.len() as u8;

        let data_len_bytes: [u8; 8] = data_len.to_be_bytes();
        buffer[2..HEADER_LENGTH].copy_from_slice(&data_len_bytes);
        Client::add_name(&mut buffer, interface_name);

        // add the interface name to the bufer
        let name_bytes = interface_name.as_bytes();

        buffer[HEADER_LENGTH..HEADER_LENGTH + interface_name.len()].copy_from_slice(name_bytes);

        // read first data chunk into free buffer space after the header and interface name
        let mut bytes_read: usize =
            pcap_file.read(&mut buffer[HEADER_LENGTH + interface_name.len()..])?;

        // send the header, interface name, and first chunk of pcap data
        tcp.write(&buffer[0..HEADER_LENGTH + interface_name.len() + bytes_read])?;
        remaining_bytes -= bytes_read as u64;

        // send file data in chunks of size BUFFER_SIZE
        while remaining_bytes > 0 {
            bytes_read = pcap_file.read(&mut buffer[HEADER_LENGTH..])?;
            remaining_bytes -= bytes_read as u64;

            tcp.write(&buffer[0..bytes_read])?;
        }

        tcp.shutdown(Shutdown::Both)?;

        Ok(())
    }
}
