use std::convert::TryFrom;
use std::fs;
use std::path::{Path, PathBuf};

use pcap::Capture;

use crate::behavior::collector::BehaviorCollector;
use crate::behavior::evaluate::BehaviorReport;
use crate::behavior::Behavior;
use crate::error::Result;
use crate::protocols::ProtocolPacket;

pub struct PcapProcessor<'a> {
    behaviors: &'a [Behavior],

    pcap_dir: PathBuf,
}

impl PcapProcessor<'_> {
    pub fn new(behaviors: &[Behavior], pcap_dir: PathBuf) -> PcapProcessor { PcapProcessor { behaviors, pcap_dir } }

    /// Iterate over server capture directory. This method will traverse only
    /// the children of the root pcap directory, and so any non-directory files
    /// in the root pcap directory will be ignored.
    pub fn process(&self) -> Result<BehaviorReport> {
        let mut collector = BehaviorCollector::new();

        for behavior in self.behaviors {
            collector.insert_behavior(behavior);
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

        Ok(collector.evaluate())
    }

    /// Process a single pcap file, by adding the found [ProtocolPacket]s
    /// into the given [BehaviorCollector].
    fn process_pcap(&self, path: &Path, collector: &mut BehaviorCollector) -> Result<()> {
        let mut capture = Capture::from_file(path)?;

        while let Ok(packet) = capture.next() {
            match ProtocolPacket::try_from(packet.data) {
                Ok(protocol_packet) =>
                    if let Err(err) = collector.insert_packet(protocol_packet) {
                        eprintln!("{}", err.to_string())
                    },
                Err(err) => eprintln!("Error parsing packet: {}", err.to_string()),
            }
        }

        Ok(())
    }
}
