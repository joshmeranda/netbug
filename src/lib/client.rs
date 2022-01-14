use std::collections::HashMap;
use std::default::Default;
use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, Shutdown, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::time::Duration;

use pcap::{Active, Capture, Device};
use tokio::runtime::Runtime;

use crate::behavior::{Behavior, BehaviorRunner};
use crate::bpf::filter::{FilterBuilder, FilterExpression, FilterOptions};
use crate::config::client::ClientConfig;
use crate::config::defaults;
use crate::error::{NbugError, Result};
use crate::{BUFFER_SIZE, MESSAGE_VERSION};

/// The main Netbug client to capture network and dump network traffic to pcap
/// files.
///
/// Note that the captured packets are not consumed and added to a save file
/// until `stop_capture` is called. To avoid capturing more data than needed,
/// set `delay` to be as small as possible, and minimize the amount of blocking
/// code between calls to `start_capture` and `stop_capture`.
///
/// todo: move the `run_behaviors` and `run_behaviors_concurrent` method's
///       internal `runtime`s out so we don't waste resource building a new
///       runtime each time we need to capture network data
/// todo: might make more sense to change `allow_concurrent` to a group of
///       sequential and a group of concurrent behaviors
/// todo: we need an actual logging framework rather than just printing to stdout
pub struct Client {
    pcap_dir: PathBuf,

    pub allow_concurrent: bool,

    // todo: this duplication of Device with a reference is likely a pretty bad idea
    //       might be better to store the capture along with its pcap or add the save_file when
    devices: Vec<Device>,

    /// It may be counterintuitive for the save file path to be the key, it is
    /// cleaner since [Capture] is not hashtable.
    captures: HashMap<PathBuf, Capture<Active>>,

    srv_addr: SocketAddr,

    behavior_runners: Vec<BehaviorRunner>,

    filter: FilterExpression,

    delay: u8,
}

impl Default for Client {
    fn default() -> Client {
        Client {
            pcap_dir:         defaults::default_pcap_dir(),
            allow_concurrent: defaults::client::default_concurrent_run(),
            devices:          vec![],
            captures: HashMap::new(),
            srv_addr:         SocketAddr::new(IpAddr::from(Ipv4Addr::LOCALHOST), defaults::default_server_port()),
            behavior_runners:        vec![],
            filter:           FilterExpression::empty(),
            delay:            1,
        }
    }
}

impl <'a> Client {
    pub fn new() -> Client { Client::default() }

    /// Construct a client from a [ClientConfig] which is consumed.
    pub fn from_config(cfg: ClientConfig) -> Client {
        // find the list of valid devices on which to start a packet capture
        let devices = Device::list().unwrap();
        let devices:Vec<Device> = devices
            .into_iter()
            .filter(|device| cfg.interfaces.contains(&device.name))
            .collect();

        let filter = match cfg.filter {
            Some(filter) => filter,
            None => {
                let behaviors = cfg.behavior_runners.iter().map(|runner| &runner.behavior);

                Client::bpf_filter(behaviors)
            },
        };

        Client {
            pcap_dir: cfg.pcap_dir,
            allow_concurrent: cfg.allow_concurrent,
            srv_addr: cfg.srv_addr,
            behavior_runners: cfg.behavior_runners,
            devices,
            captures: HashMap::new(),
            filter,
            delay: cfg.delay,
        }
    }

    /// Run all client behaviors sequentially.
    pub fn run_behaviors(&self) -> Result<()> {
        let runtime = Runtime::new().unwrap();

        runtime.block_on(async {
            for runner in &self.behavior_runners {
                runner.run()?;
            }

            Ok(())
        })
    }

    /// Run all client behaviors concurrently. Note that this function blocks
    /// until all behaviors have finished.
    pub fn run_behaviors_concurrent(&self) -> Result<()> {
        if !self.allow_concurrent {
            Err(NbugError::Client(String::from(
                "Cannot run client behaviors concurrently when 'allow_concurrent' is false",
            )))
        } else {
            let mut behaviors = vec![];

            for runner in &self.behavior_runners {
                match runner.run() {
                    Ok(f) => behaviors.push(f),
                    Err(err) => eprintln!("Error running behavior: {}, {:?}", err, runner.behavior),
                }
            }

            let runtime = Runtime::new().unwrap();

            runtime.block_on(async {
                let parent_future = futures::future::join_all(behaviors);

                // todo: this needs a much bette error message (ideally it would show why the behavior failed)
                match parent_future.await.iter().find(|r| r.is_err()) {
                    Some(Err(err)) => Err(NbugError::Client(format!("An error occurred running behaviors: {:?}", err))),
                    None => Ok(()),
                    _ => unreachable!(),
                }
            })
        }
    }

    /// Begin capturing packets on the configured network devices. Note that
    /// there is currently no explicit way to end capture and flush its
    /// output, be mindful of your client's scoping to prevent capturing
    /// unnecessary packets. The resulting captures will always be in sequential
    /// order.
    ///
    /// todo: make the two errors at the top distinct, to allow the user more
    ///       control over how to handle each unique situation
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

        for device in &self.devices {
            let save_file_path = self.pcap_dir.join(format!("{}.pcap", device.name));
            let mut capture = Capture::from_device(device.clone())?.timeout(1).open()?.setnonblock()?;

            if let Err(err) = capture.filter(self.filter.to_string().as_str()) {
                return Err(NbugError::Client(format!(
                    "Error adding filter to capture: {}",
                    err
                )))
            }

            self.captures.insert(save_file_path, capture);

            println!("Started capture for device '{}'", device.name.as_str());
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
        // each save file should be dropped and flushed since they will go out
        // of scope after their use in this loops
        for (save_file_path, mut capture) in self.captures.drain() {
            let mut save_file = capture.savefile(save_file_path).unwrap(); // todo: we need to handle this error eventually

            while let Ok(packet) = capture.next() {
                save_file.write(&packet);
            }
        }

        Ok(())
    }

    /// Determine if the client is capturing network traffic.
    pub fn is_capturing(&self) -> bool {
        ! self.captures.is_empty()
    }

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
        stream.write_all(&[MESSAGE_VERSION, interface_name.len() as u8])?;

        let data_len_bytes: [u8; 8] = data_len.to_be_bytes();
        stream.write_all(&data_len_bytes)?;

        // add the interface name to the buffer
        let name_bytes = interface_name.as_bytes();
        stream.write_all(name_bytes)?;

        io::copy(&mut pcap_file, stream)?;

        Ok(())
    }

    /// Generate the bpf filter to use to minimize the data captured by the
    /// client.
    fn bpf_filter<I>(behaviors: I) -> FilterExpression
        where I: Iterator<Item = &'a Behavior> + ExactSizeIterator
    {
        // using len here since `ExactSizeIterator::is_empty` is unstable
        if behaviors.len() == 0 {
            return FilterExpression::empty();
        }

        let options = FilterOptions::new();
        let mut iter = behaviors.map(|behavior| behavior.as_filter(&options));

        let mut builder = FilterBuilder::with_filter(iter.next().unwrap().unwrap());

        for filter in iter {
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

    #[test]
    fn test_filter_builder() {
        let icmp: Behavior = toml::from_str("src = \"127.0.0.1\"\ndst = \"8.8.8.8\"\nprotocol = \"icmp\"").unwrap();
        let tcp: Behavior = toml::from_str("src = \"127.0.0.1\"\ndst = \"8.8.8.8:80\"\nprotocol = \"tcp\"").unwrap();

        let mut behaviors = Vec::new();
        behaviors.push(icmp);
        behaviors.push(tcp);

        assert_eq!(
            Client::bpf_filter(behaviors.iter()).to_string(),
            "(icmp and ((host 127.0.0.1) or (host 8.8.8.8))) or (tcp and ((host 127.0.0.1) or (host 8.8.8.8 and port \
             80)))"
        );
    }
}
