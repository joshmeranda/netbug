use std::default::Default;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::thread::{Builder, JoinHandle};
use std::time::Duration;

use pcap::{Capture, Device};

use crate::behavior::Behavior;
use crate::bpf::filter::{FilterBuilder, FilterExpression, FilterOptions};
use crate::config::client::ClientConfig;
use crate::config::defaults;
use crate::error::{NbugError, Result};
use crate::{BUFFER_SIZE, MESSAGE_VERSION};

/// The main Netbug client to capture network and dump network traffic to pcap
/// files.
pub struct Client {
    pcap_dir: PathBuf,

    pub allow_concurrent: bool,

    devices: Vec<Device>,

    capturing: Arc<AtomicBool>,

    srv_addr: SocketAddr,

    behaviors: Vec<Behavior>,

    filter: FilterExpression,

    delay: u8,
}

impl Default for Client {
    fn default() -> Client {
        Client {
            pcap_dir:         defaults::default_pcap_dir(),
            allow_concurrent: defaults::client::default_concurrent_run(),
            devices:          vec![],
            capturing:        Arc::new(AtomicBool::new(false)),
            srv_addr:         SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), defaults::default_server_port()),
            behaviors:        vec![],
            filter:           FilterExpression::empty(),
            delay:            1,
        }
    }
}

impl Client {
    pub fn new() -> Client { Client::default() }

    /// Construct a client from a [ClientConfig] which is consumed.
    pub fn from_config(cfg: ClientConfig) -> Client {
        // find the list of valid devices on which to start a packet capture
        let devices = Device::list().unwrap();
        let devices: Vec<Device> = devices
            .into_iter()
            .filter(|device| cfg.interfaces.contains(&device.name))
            .collect();
        let filter = match cfg.filter {
            Some(filter) => filter,
            None => Client::bpf_filter(&cfg.behaviors),
        };

        Client {
            pcap_dir: cfg.pcap_dir,
            allow_concurrent: cfg.allow_concurrent,
            srv_addr: cfg.srv_addr,
            behaviors: cfg.behaviors,
            devices,
            filter,
            capturing: Arc::new(AtomicBool::new(false)),
            delay: cfg.delay,
        }
    }

    /// Run all client behaviors sequentially.
    pub fn run_behaviors(&self) -> Result<()> {
        for behavior in &self.behaviors {
            Client::run_behavior(behavior);
        }

        Ok(())
    }

    /// Run all client behaviors concurrently. Note that this function blocks
    /// until all behaviors have finished.
    pub fn run_behaviors_concurrent(&self) -> Result<()> {
        if !self.allow_concurrent {
            return Err(NbugError::Client(String::from(
                "Cannot run client behaviors concurrently when 'allow_concurrent' is false",
            )));
        }

        let mut handles = Vec::<JoinHandle<()>>::with_capacity(self.behaviors.len());
        for behavior in &self.behaviors {
            let builder = thread::Builder::new();

            unsafe {
                // this is safe since all threads are joined before the method returns
                handles.push(builder.spawn_unchecked(move || Client::run_behavior(&behavior))?);
            }
        }

        for handle in handles {
            if let Err(_) = handle.join() {
                eprintln!("Error waiting for behavior thread to finish");
            }
        }

        Ok(())
    }

    fn run_behavior(behavior: &Behavior) {
        if let Err(err) = behavior.run() {
            eprintln!("Error running behavior: {}, {:?}", err.to_string(), behavior);
        }
    }

    /// Begin capturing packets on the configured network devices. Note that
    /// there is currently no explicit way to end capture and flush its
    /// output, be mindful of your client's scoping to prevent capturing
    /// unnecessary packets. The resulting captures will always be in sequential
    /// order.
    pub fn start_capture(&mut self) -> Result<()> {
        if self.is_capturing() {
            return Err(NbugError::Client(String::from("capture is already running")));
        } else if self.devices.is_empty() {
            return Err(NbugError::Client(String::from("no configured network devices")));
        }

        // ensure that the packet capture directory exists
        if !self.pcap_dir.exists() {
            fs::create_dir_all(self.pcap_dir.clone())?;
        }

        self.capturing.store(true, Ordering::SeqCst);

        for device in &self.devices {
            let capture_flag = Arc::clone(&self.capturing);
            let device_name = String::from(device.name.clone());

            let mut capture = Capture::from_device(device.clone())?.timeout(1).open()?.setnonblock()?;

            if let Err(err) = capture.filter(self.filter.to_string().as_str()) {
                return Err(NbugError::Client(
                    format!("Error adding filter to capture: {}", err.to_string()).to_owned(),
                ));
            }

            let mut pcap_path = PathBuf::from(&self.pcap_dir);
            pcap_path.push(format!("{}.pcap", &device_name));

            let mut save_file = capture.savefile(pcap_path).unwrap();

            // todo: add timestamp to end of pcap name
            let builder = Builder::new().name(device_name.clone());
            builder.spawn(move || {
                while capture_flag.load(Ordering::SeqCst) {
                    match capture.next() {
                        Ok(packet) => save_file.write(&packet),
                        Err(_) => {}, // todo: these errors should be handled
                    }
                }

                // force immediate pcap dump
                std::mem::drop(save_file);
            })?;

            println!("Started capture for device '{}'", device_name)
        }

        Ok(())
    }

    /// Signal the client to stop capturing network packets, after the
    /// configured delay period. Note that this simply signals the capturing
    /// thread loops to discontinue iteration rather than immediately
    /// stopping them. Therefore, it is possible for extra packets to be
    /// captured and written to the resulting pcap between the time this
    /// function is called and the signal is received.
    pub fn stop_capture(&mut self) -> Result<()> {
        std::thread::sleep(Duration::from_secs(self.delay as u64));

        self.stop_capture_now()
    }

    fn stop_capture_now(&mut self) -> Result<()> {
        if !self.is_capturing() {
            return Err(NbugError::Client(String::from("no capture is running")));
        }

        self.capturing.store(false, Ordering::SeqCst);

        Ok(())
    }

    /// Determine if the client is capturing network traffic.
    pub fn is_capturing(&self) -> bool { self.capturing.load(Ordering::SeqCst) }

    /// Transfer all pcaps to the server.
    pub fn transfer_all(&self) -> Result<()> {
        let stream = TcpStream::connect(self.srv_addr)?;
        let mut writer = BufWriter::with_capacity(BUFFER_SIZE, stream);

        for device in &self.devices {
            self.transfer_pcap(device.name.as_str(), &mut writer)?;
        }

        let stream = writer.into_inner().unwrap();
        stream.shutdown(Shutdown::Both)?;

        Ok(())
    }

    /// Transfer a single pcap to the server according to the captured interface
    /// name.
    fn transfer_pcap(&self, interface_name: &str, stream: &mut BufWriter<TcpStream>) -> Result<()> {
        // construct the path to the interface's pcap file
        let mut pcap_path = self.pcap_dir.to_path_buf();
        pcap_path.push(format!("{}.pcap", interface_name));

        let mut pcap_file = File::open(&pcap_path)?;

        // get the amount of bytes in the pcap files
        let data_len = fs::metadata(&pcap_path)?.len();

        // fill the header bytes with the relevant behavior
        stream.write(&[MESSAGE_VERSION, interface_name.len() as u8]);

        let data_len_bytes: [u8; 8] = data_len.to_be_bytes();
        stream.write(&data_len_bytes);

        // add the interface name to the buffer
        let name_bytes = interface_name.as_bytes();
        stream.write(&name_bytes);

        io::copy(&mut pcap_file, stream);

        Ok(())
    }

    /// Generate the bpf filter to use to minimize the data captured by the
    /// client.
    fn bpf_filter(behaviors: &[Behavior]) -> FilterExpression {
        if behaviors.is_empty() {
            return FilterExpression::empty();
        }

        let options = FilterOptions::new();
        let mut iter = behaviors.iter().map(|behavior| behavior.as_filter(&options));

        let mut builder = FilterBuilder::with_filter(iter.next().unwrap().unwrap());
        while let Some(filter) = iter.next() {
            match filter {
                Some(f) => builder.or_filter(f),
                None => eprintln!("Could not build a BPF filter "),
            }
        }

        builder.build()
    }
}

#[cfg(test)]
mod test {
    use crate::behavior::Behavior;
    use crate::client::Client;
    use crate::protocols::ProtocolNumber;

    #[test]
    fn test_filter_builder() {
        let icmp: Behavior = toml::from_str("src = \"127.0.0.1\"\ndst = \"8.8.8.8\"\nprotocol = \"icmp\"").unwrap();
        let tcp: Behavior = toml::from_str("src = \"127.0.0.1\"\ndst = \"8.8.8.8:80\"\nprotocol = \"tcp\"").unwrap();

        let mut behaviors = Vec::new();
        behaviors.push(icmp);
        behaviors.push(tcp);

        assert_eq!(
            Client::bpf_filter(behaviors.as_slice()).to_string(),
            "(icmp and ((host 127.0.0.1) or (host 8.8.8.8))) or (tcp and ((host 127.0.0.1) or (host 8.8.8.8 and port \
             80)))"
        );
    }
}
