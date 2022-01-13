//! Defines many structs and packet serialization from raw packet data. These
//! will largely focus on packets headers, and will largely ignore any packet
//! payloads, as they are largely irrelevant to this project.

use std::convert::TryFrom;
use std::net::{IpAddr, SocketAddr};

use crate::error::NbugError;
use crate::protocols::ethernet::IeeEthernetPacket;
use crate::protocols::icmp::icmpv4::Icmpv4Packet;
use crate::protocols::icmp::icmpv6::Icmpv6Packet;
use crate::protocols::ip::{IpPacket, Ipv4Packet, Ipv6Packet};
use crate::protocols::tcp::TcpPacket;
use crate::protocols::udp::UdpPacket;
use crate::Addr;

pub mod ethernet;
pub mod icmp;
pub mod ip;
pub mod tcp;
pub mod udp;

pub static SRC_ADDR_KEY: &str = "SrcAddr";
pub static SRC_PORT_KEY: &str = "SrcPort";

pub static DST_ADDR_KEY: &str = "DstAddr";
pub static DST_PORT_KEY: &str = "DstPort";

/// Wrapper around the official [protocol number](https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml)
/// provided by the IANA.
#[derive(Copy, Clone, Debug, Deserialize, Eq, FromPrimitive, Hash, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ProtocolNumber {
    HopOpt           = 0,
    Icmp             = 1,
    Igmp             = 2,
    Ggp              = 3,
    Ipv4             = 4,
    St               = 5,
    Tcp              = 6,
    Cbt              = 7,
    Egp              = 8,
    Igp              = 9,
    BbnRccMon        = 10,
    NvpII            = 11,
    Pip              = 12,
    ArgusDEPRECATED  = 13,
    Emcon            = 14,
    Xnet             = 15,
    Choas            = 16,
    Udp              = 17,
    Mux              = 18,
    DcnMeas          = 19,
    Hmp              = 20,
    Prm              = 21,
    XnsIdp           = 22,
    Trunk1           = 23,
    Trunk2           = 24,
    Leaf1            = 25,
    LEaf2            = 26,
    Rdp              = 27,
    Irtp             = 28,
    IsoTr4           = 29,
    NetBlt           = 30,
    MfeNsp           = 31,
    MeritInp         = 32,
    Dccp             = 33,
    Tpc              = 34, // third party connect protocol
    Idpr             = 35,
    Xtp              = 36,
    Ddp              = 37,
    IdprCmtp         = 38,
    TpPP             = 39, // TP++
    Il               = 40,
    Ipv6             = 41,
    Sdrp             = 42,
    Ipv6Route        = 43,
    Ipv6Frag         = 44,
    Idrp             = 45,
    Rsvp             = 46,
    Gre              = 47,
    Dsr              = 48,
    Bna              = 49,
    Esp              = 50,
    Ah               = 51,
    INlsp            = 52,
    SwipeDEPRECATED  = 53,
    Narp             = 54,
    Mobile           = 55,
    Tlep             = 56,
    Skip             = 57,
    Ipv6Icmp         = 58,
    Ipv6NoNxt        = 59,
    Ipv6Opts         = 60,
    AnyHostInternaProtocol = 61,
    Cftp             = 62,
    AnyLocalNetwork  = 63,
    SatExpak         = 64,
    Kryptolan        = 65,
    Rvd              = 66,
    Ippc             = 67,
    AnyDistributedFileSystem = 68,
    SatMon           = 69,
    Visa             = 70,
    Ipcv             = 71,
    Cpnx             = 72,
    Cphb             = 73,
    Wsn              = 74,
    Pvp              = 75,
    BrSatMon         = 76,
    SunNd            = 77,
    WbMon            = 78,
    WbExpak          = 79,
    IsoIp            = 80,
    Vmtp             = 81,
    SecureVmpt       = 82,
    Vines            = 83,
    TtpIptm          = 84,
    NsfnetIgp        = 85,
    Dgp              = 86,
    Tcf              = 87,
    Eigrp            = 88,
    Osifigp          = 89,
    SpriteRpc        = 90,
    Larp             = 91,
    Mtp              = 92,
    Ax25             = 93,
    Ipip             = 94,
    MicpDEPRECATED   = 95,
    SccSp            = 96,
    EtherIp          = 97,
    Encap            = 98,
    Gmpt             = 100,
    Ifmp             = 101,
    Pnni             = 102,
    Pim              = 103,
    Aris             = 104,
    Scps             = 105,
    Qnx              = 106,
    ActiveNetworks   = 107,
    IPComp           = 108,
    Snp              = 109,
    CompaqPeer       = 110,
    IpxInIp          = 111,
    Vrrp             = 112,
    Pgm              = 113,
    AnyNoHopProtocol = 114,
    L2TP             = 115,
    Dddx             = 116,
    Iatp             = 117,
    Stp              = 118,
    Srp              = 119,
    Uti              = 120,
    Smp              = 121,
    SmDEPRECATED     = 122,
    Ptp              = 123,
    IsisOverIpv4     = 124,
    Fire             = 125,
    CRrtp            = 126,
    Crudp            = 127,
    Sscopmce         = 128,
    Iplt             = 129,
    Ssp              = 130,
    Pipe             = 131,
    Sctp             = 132,
    Fc               = 133,
    RsvpE2eIgnore    = 134,
    MobilityHeader   = 135,
    UcpLite          = 136,
    MplsInIp         = 137,
    Manet            = 138,
    Hip              = 139,
    Shim6            = 140,
    Wesp             = 141,
    Rohc             = 142,
    Ethernet         = 143,
    // numbers 144 - 252 are unassigned and FromPrimitive should return None
    Testing1         = 253,
    Testing2         = 254,
    Reserved         = 255,
}

#[derive(Clone)]
pub enum ProtocolHeader {
    Icmpv4(Icmpv4Packet),
    Icmpv6(Icmpv6Packet),
    Tcp(TcpPacket),
    Udp(UdpPacket),
}

impl ProtocolHeader {
    pub fn header_length(&self) -> usize { todo!() }

    /// Retrieve the [ProtocolNumber] for this header.
    pub fn protocol(&self) -> ProtocolNumber {
        match self {
            ProtocolHeader::Icmpv4(..) => ProtocolNumber::Icmp,
            ProtocolHeader::Icmpv6(..) => ProtocolNumber::Ipv6Icmp,
            ProtocolHeader::Tcp(..) => ProtocolNumber::Tcp,
            ProtocolHeader::Udp(..) => ProtocolNumber::Udp,
        }
    }
}

#[derive(Clone)]
pub struct ProtocolPacket {
    pub ether: IeeEthernetPacket,

    pub ip: IpPacket,

    pub header: ProtocolHeader,

    pub source: Addr,

    pub destination: Addr,
}

impl ProtocolPacket {
    pub fn new(ether: IeeEthernetPacket, ip: IpPacket, header: ProtocolHeader) -> ProtocolPacket {
        let (source, destination) = ProtocolPacket::make_addr(&ip, &header);

        ProtocolPacket {
            ether,
            ip,
            header,
            source,
            destination,
        }
    }

    /// Utility to create the source and destination addresses from the given
    /// [IpPacket] and [ProtocolHeader].
    fn make_addr(ip: &IpPacket, header: &ProtocolHeader) -> (Addr, Addr) {
        let src_ip = match ip {
            IpPacket::V4(packet) => IpAddr::V4(packet.source),
            IpPacket::V6(packet) => IpAddr::V6(packet.source),
        };
        let src = match header {
            ProtocolHeader::Icmpv4(_) | ProtocolHeader::Icmpv6(_) => Addr::Internet(src_ip),
            ProtocolHeader::Tcp(header) => Addr::Socket(SocketAddr::new(src_ip, header.source_port)),
            ProtocolHeader::Udp(header) => Addr::Socket(SocketAddr::new(src_ip, header.source_port)),
        };

        let dst_ip = match ip {
            IpPacket::V4(packet) => IpAddr::V4(packet.destination),
            IpPacket::V6(packet) => IpAddr::V6(packet.destination),
        };
        let dst = match header {
            ProtocolHeader::Icmpv4(_) | ProtocolHeader::Icmpv6(_) => Addr::Internet(dst_ip),
            ProtocolHeader::Tcp(header) => Addr::Socket(SocketAddr::new(src_ip, header.destination_port)),
            ProtocolHeader::Udp(header) => Addr::Socket(SocketAddr::new(src_ip, header.destination_port)),
        };

        (src, dst)
    }
}

impl TryFrom<&[u8]> for ProtocolPacket {
    type Error = NbugError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        let mut offset = 0;

        let ether = IeeEthernetPacket::try_from(data)?;
        offset += match ether {
            IeeEthernetPacket::Ieee8022(_) => ethernet::Ethernet2Packet::MIN_BYTES,
            IeeEthernetPacket::Ieee8023(_) => ethernet::Ethernet3Packet::MIN_BYTES,
        };

        let ip = IpPacket::try_from(&data[offset..])?;
        offset += match ip {
            IpPacket::V4(_) => Ipv4Packet::MIN_BYTES,
            IpPacket::V6(_) => Ipv6Packet::MIN_BYTES,
        };

        let header = match ip.protocol() {
            ProtocolNumber::Icmp => ProtocolHeader::Icmpv4(Icmpv4Packet::try_from(&data[offset..])?),
            ProtocolNumber::Ipv6Icmp => ProtocolHeader::Icmpv6(Icmpv6Packet::try_from(&data[offset..])?),
            ProtocolNumber::Tcp => ProtocolHeader::Tcp(TcpPacket::try_from(&data[offset..])?),
            ProtocolNumber::Udp => ProtocolHeader::Udp(UdpPacket::try_from(&data[offset..])?),
            number =>
                return Err(NbugError::Packet(format!(
                    "Unsupported or invalid protocol number: {}",
                    number as u8
                ))),
        };

        Ok(ProtocolPacket::new(ether, ip, header))
    }
}
