use std::convert::TryFrom;
use std::path::{Path, PathBuf};

use pcap::Capture;


use crate::error::Result;
use crate::protocols::ethernet::IeeEthernetPacket;
use crate::protocols::icmp::icmpv4::Icmpv4Packet;
use crate::protocols::icmp::icmpv6::Icmpv6Packet;
use crate::protocols::icmp::IcmpPacket;
use crate::protocols::ip::IpPacket;
use crate::protocols::{ProtocolPacketHeader, ProtocolNumber};
use std::fs;

pub struct PcapProcessor {
    pcap_dir: PathBuf,
}

impl PcapProcessor {
    pub fn process(&self) -> Result<()> {
        for entry in fs::read_dir(&self.pcap_dir)? {
            self.process_pcap(entry.unwrap().path());
        }

        Ok(())
    }

    fn process_pcap(&self, path: PathBuf) -> Result<()> {
        let mut capture = Capture::from_file(path)?;

        while let Ok(packet) = capture.next() {
            let ethernet = IeeEthernetPacket::try_from(packet.data)?;
            let ip = IpPacket::try_from(&packet.data[ethernet.header_length()..])?;

            match ip.protocol_type() {
                ProtocolNumber::Icmp => println!("icmp"),
                ProtocolNumber::Ipv6Icmp => println!("icmp6"),
                ProtocolNumber::Tcp => println!("tcp"),
                ProtocolNumber::Udp => println!("udp"),
                _ => println!("else"),
            }
        }

        Ok(())
    }
}
