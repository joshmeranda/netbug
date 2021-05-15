use std::net::IpAddr;
use std::ops::Range;
use std::iter;

use crate::bpf::expression::{Expression, BinOp};
use crate::bpf::Token;
use std::slice::Iter;
use crate::bpf::filter::{FormatOptions, TokenStream};
use crate::bpf::primitive::Primitive::IsoProto;

// todo: use something like https://docs.rs/strum/0.20.0/strum/index.html to generate enum names as str

// todo: needs better NetMask type
pub type NetMask = IpAddr;
pub type Host = String;

///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, PartialEq)]
pub enum Identifier {
    Addr(IpAddr),
    Host(Host),
    NetMask(NetMask),
    Port(u16),
    RangeStart(u16),
    RangeEnd(u16),
    Llc(LlcType),
    Len(usize),
    Protocol(Protocol),
    Interface(String),
    RuleNum(usize),
    RuleSet(String),
    Code(ReasonCode),
    Action(Action),
    WlanType(WlanType),
    WlanSubType(WlanSubType),
    Dir(Direction),
    VlanId(usize),
    LabelNum(usize),
    SessionId(usize),
    VirtualNetworkIdentifier(usize),
    VirtualPathIdentifier(usize),
    VirtualChannelIdentifier(usize),
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, PartialEq)]
enum LlcType {
    I,
    S,
    U,
    Rr,
    Rnr,
    Rej,
    Ui,
    Ua,
    Disc,
    Sabme,
    Test,
    Xid,
    Frmr,
}

impl AsRef<str> for LlcType {
    fn as_ref(&self) -> &str {
        match self {
            LlcType::I => "i",
            LlcType::S => "s",
            LlcType::U => "u",
            LlcType::Rr => "rr",
            LlcType::Rnr => "rnr",
            LlcType::Rej => "rej",
            LlcType::Ui => "ui",
            LlcType::Ua => "ua",
            LlcType::Disc => "disc",
            LlcType::Sabme => "sabme",
            LlcType::Test => "test",
            LlcType::Xid => "xid",
            LlcType::Frmr => "frmr",
        }
    }
}

impl TokenStream for LlcType {
    fn stream(&self) -> core::slice::Iter<Token> {
        vec![Token::Id(Identifier::Llc(self.clone()))]
            .iter()
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, PartialEq)]
pub enum ReasonCode {
    Match,
    BadOffset,
    Fragment,
    Short,
    Normalize,
    Memory,
}

impl AsRef<str> for ReasonCode {
    fn as_ref(&self) -> &str {
        match self {
            ReasonCode::Match => "match",
            ReasonCode::BadOffset => "bad-offset",
            ReasonCode::Fragment => "fragment",
            ReasonCode::Short => "short",
            ReasonCode::Normalize => "normalize",
            ReasonCode::Memory => "memory",
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, PartialEq)]
pub enum Action {
    Pass,
    Block,
    Nat,
    Rdr,
    Binat,
    Scrub,
}

impl AsRef<str> for Action {
    fn as_ref(&self) -> &str {
        match self {
            Action::Pass => "paas",
            Action::Block => "block",
            Action::Nat => "nat",
            Action::Rdr => "rdr",
            Action::Binat => "binat",
            Action::Scrub => "scrub",
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, PartialEq)]
enum WlanType {
    Mgt,
    Ctl,
    Data,
}

#[derive(Clone, Debug, PartialEq)]
enum WlanSubType {
    // mgt
    AssocReq,
    AssocResp,
    ReAssocReq,
    ReAssocResp,
    ProbeReq,
    ProbeResp,
    Beacon,
    Atim,
    DisAssoc,
    Auth,
    DeAuth,

    // ctl
    PsPoll,
    Rts,
    Cts,
    Ack,
    CfEnd,
    CfEndAck,

    // data
    Data,
    DataCfAck,
    DataCfPoll,
    DataCfAckPoll,
    Null,
    CfAck,
    CfPoll,
    CfAckPoll,
    QosData,
    QosDataCfPoll,
    QosDataCfAckPoll,
    Qos,
    QosCfPoll,
    QosCfAckPoll,
}

impl AsRef<str> for WlanType {
    fn as_ref(&self) -> &str {
        match self {
            WlanType::Mgt => "mgt",
            WlanType::Ctl => "ctl",
            WlanType::Data => "data",
        }
    }
}

impl AsRef<str> for WlanSubType {
    fn as_ref(&self) -> &str {
        match self {
            WlanSubType::AssocReq => "assoc-req",
            WlanSubType::AssocResp => "assoc-resp",
            WlanSubType::ReAssocReq => "reassoc-req",
            WlanSubType::ReAssocResp => "reassoc-resp",
            WlanSubType::ProbeReq => "probe-req",
            WlanSubType::ProbeResp => "probe-resp",
            WlanSubType::Beacon => "beacon",
            WlanSubType::Atim => "atim",
            WlanSubType::DisAssoc => "disassoc",
            WlanSubType::Auth => "auth",
            WlanSubType::DeAuth => "deauth",
            WlanSubType::PsPoll => "ps-poll",
            WlanSubType::Rts => "rts",
            WlanSubType::Cts => "cts",
            WlanSubType::Ack => "ack",
            WlanSubType::CfEnd => "cf-end",
            WlanSubType::CfEndAck => "cf-end-ack",
            WlanSubType::Data => "data",
            WlanSubType::DataCfAck => "data-cf-ack",
            WlanSubType::DataCfPoll => "data-cf-poll",
            WlanSubType::DataCfAckPoll => "data-cf-ack-poll",
            WlanSubType::Null => "null",
            WlanSubType::CfAck => "cf-ack",
            WlanSubType::CfPoll => "cf-poll",
            WlanSubType::CfAckPoll => "cf-ack-poll",
            WlanSubType::QosData => "qos-data",
            WlanSubType::QosDataCfPoll => "qos-data-cf-poll",
            WlanSubType::QosDataCfAckPoll => "qos-data-cf-ack-poll",
            WlanSubType::Qos => "qos",
            WlanSubType::QosCfPoll => "qos-cf-poll",
            WlanSubType::QosCfAckPoll => "qos-cf-ack-poll",
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, PartialEq)]
pub enum RelOp {
    Gt,
    Lt,
    Gte,
    Lte,
    Eq,
    Neq,
}

impl AsRef<str> for RelOp {
    fn as_ref(&self) -> &str {
        match self {
            RelOp::Gt => ">",
            RelOp::Lt => "<",
            RelOp::Gte => ">=",
            RelOp::Lte => "<=",
            RelOp::Eq => "=",
            RelOp::Neq => "!=",
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, PartialEq)]
pub enum Qualifier {
    Host,

    Ether,

    Gateway,

    Net,
    Mask,

    Port,

    Less,
    Greater,

    ProtoRaw,

    ProtoAbbr(ProtoAbbr),

    PortRange,

    ProtoChain,

    Multicast,
    Broadcast,

    EtherAbbr(EtherAbbr),

    Decnet,

    Llc,

    Inbound,
    Outbound,

    Ifname,
    On,

    Rnr,
    RuleNum,

    Reason,

    Rset,
    RuleSet,

    Action,

    Srnr,
    SubRuleNum,

    Wlan,

    // follows wlan
    Ra,
    Ta,
    Addr1,
    Addr2,
    Addr3,
    Addr4,

    WlanType,
    WlanSubType,

    RawDir,

    Vlan,

    Mpls,

    PppOverEtherDiscovery, // pppoed
    PppOverEtherSession,   // pppoes

    Geneve,

    Iso,

    IsoAbbr(IsoProtocol), // Abbreviations clnp, esis, isis

    L1,
    L2,
    Iih,
    Lsp,
    Snp,
    Csnp,
    Psnp,

    VirtualPathIdentifier,
    VirtualChannelIdentifier,

    Lane,

    Oamf4s,
    Oamf4e,
    Oamf4,
    Oam,

    MetaSignallingCircuit, // metac

    BroadcastSignalingCircuit, // bcc

    SignallingCircuit, // sc,

    IlmiCircuit, // IlmiCircuit

    ConnectMsg,

    MetaConnect,

    Type(QualifierType),
    Dir(QualifierDirection),
    Proto(QualifierProtocol),
}

#[derive(Clone, Debug, PartialEq)]
enum QualifierType {
    Host,
    Net,
    Port,
    PortRange,
}

#[derive(Clone, Debug, PartialEq)]
pub enum QualifierProtocol {
    Ether,
    Fddi,
    Tr,
    Wlan,
    Icmp,
    Ip,
    Ip6,
    Arp,
    Rarp,
    Decnet,
    Tcp,
    Udp,
}

#[derive(Clone, Debug, PartialEq)]
enum QualifierDirection {
    General(Direction),
    Wlan(WlanDirection),
}

impl AsRef<str> for Qualifier {
    fn as_ref(&self) -> &str {
        match self {
            Qualifier::Host => "host",
            Qualifier::Ether => "ether",
            Qualifier::Net => "net",
            Qualifier::Gateway => "gateway",
            Qualifier::Mask => "mask",
            Qualifier::Port => "port",
            Qualifier::Less => "less",
            Qualifier::Greater => "greater",
            Qualifier::ProtoRaw => "proto",
            Qualifier::ProtoAbbr(abbr) => abbr.as_ref(),
            Qualifier::PortRange => "portrange",
            Qualifier::ProtoChain => "protochain",
            Qualifier::Multicast => "multicast",
            Qualifier::Broadcast => "broadcast",
            Qualifier::EtherAbbr(abbr) => abbr.as_ref(),
            Qualifier::Decnet => "decnet",
            Qualifier::Llc => "llc",
            Qualifier::Inbound => "inbound",
            Qualifier::Outbound => "outbound",
            Qualifier::Ifname => "ifname",
            Qualifier::On => "on",
            Qualifier::Rnr => "rnr",
            Qualifier::RuleNum => "rulenum",
            Qualifier::Reason => "reason",
            Qualifier::Rset => "rset",
            Qualifier::RuleSet => "ruleset",
            Qualifier::Action => "action",
            Qualifier::Srnr => "srnr",
            Qualifier::SubRuleNum => "subrulenum",
            Qualifier::Wlan => "wlan",
            Qualifier::Ra => "Ra",
            Qualifier::Ta => "ta",
            Qualifier::Addr1 => "addr1",
            Qualifier::Addr2 => "addr2",
            Qualifier::Addr3 => "addr3",
            Qualifier::Addr4 => "addr4",
            Qualifier::WlanType => "type",
            Qualifier::WlanSubType => "subtype",
            Qualifier::RawDir => "dir",
            Qualifier::Vlan => "vlan",
            Qualifier::Mpls => "mpls",
            Qualifier::PppOverEtherDiscovery => "pppoed",
            Qualifier::PppOverEtherSession => "pppoes",
            Qualifier::Geneve => "geneve",
            Qualifier::Iso => "iso",
            Qualifier::IsoAbbr(abbr) => abbr.as_ref(),
            Qualifier::L1 => "l1",
            Qualifier::L2 => "l2",
            Qualifier::Iih => "iih",
            Qualifier::Lsp => "lsp",
            Qualifier::Snp => "snp",
            Qualifier::Csnp => "cnsp",
            Qualifier::Psnp => "psnp",
            Qualifier::VirtualPathIdentifier => "vpi",
            Qualifier::VirtualChannelIdentifier => "vci",
            Qualifier::Lane => "lane",
            Qualifier::Oamf4s => "oamf4s",
            Qualifier::Oamf4e => "oamf4e",
            Qualifier::Oamf4 => "oamf4",
            Qualifier::Oam => "oam",
            Qualifier::MetaSignallingCircuit => "metac",
            Qualifier::BroadcastSignalingCircuit => "bcc",
            Qualifier::SignallingCircuit => "sc",
            Qualifier::IlmiCircuit => "ilmic",
            Qualifier::ConnectMsg => "connectmsg",
            Qualifier::MetaConnect => "metaconnect",
            Qualifier::Type(t) => t.as_ref(),
            Qualifier::Dir(dir) => dir.as_ref(),
            Qualifier::Proto(proto) => proto.as_ref(),
        }
    }
}

impl AsRef<str> for QualifierType {
    fn as_ref(&self) -> &str {
        match self {
            QualifierType::Host => "host",
            QualifierType::Net => "net",
            QualifierType::Port => "port",
            QualifierType::PortRange => "portsrange",
        }
    }
}

impl AsRef<str> for QualifierDirection {
    fn as_ref(&self) -> &str {
        match self {
            QualifierDirection::General(dir) => dir.as_ref(),
            QualifierDirection::Wlan(dir) => dir.as_ref(),
        }
    }
}

impl AsRef<str> for QualifierProtocol {
    fn as_ref(&self) -> &str {
        match self {
            QualifierProtocol::Ether => "ether",
            QualifierProtocol::Fddi => "fddi",
            QualifierProtocol::Tr => "tr",
            QualifierProtocol::Wlan => "wlan",
            QualifierProtocol::Ip => "ip",
            QualifierProtocol::Ip6 => "ip6",
            QualifierProtocol::Arp => "arp",
            QualifierProtocol::Rarp => "rarp",
            QualifierProtocol::Decnet => "decent",
            QualifierProtocol::Tcp => "tcp",
            QualifierProtocol::Udp => "udp",
            QualifierProtocol::Icmp => "icmp",
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, PartialEq)]
pub enum ProtoAbbr {
    Tcp,
    Udp,
    Icmp,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EtherAbbr {
    Ip,
    Ip6,
    Arp,
    Rarp,
    Atalk,
    Aarp,
    Decnet,
    Iso,
    Stp,
    Ipx,
    Netbui,
    Lat,
    Moprc,
    Mopdl,
}

impl AsRef<str> for ProtoAbbr {
    fn as_ref(&self) -> &str {
        match self {
            ProtoAbbr::Tcp => "tcp",
            ProtoAbbr::Udp => "udp",
            ProtoAbbr::Icmp => "icmp",
        }
    }
}

impl AsRef<str> for EtherAbbr {
    fn as_ref(&self) -> &str {
        match self {
            EtherAbbr::Ip => "ip",
            EtherAbbr::Ip6 => "ip6",
            EtherAbbr::Arp => "arp",
            EtherAbbr::Rarp => "rarp",
            EtherAbbr::Atalk => "atalk",
            EtherAbbr::Aarp => "aarp",
            EtherAbbr::Decnet => "decnet",
            EtherAbbr::Iso => "iso",
            EtherAbbr::Stp => "stpm",
            EtherAbbr::Ipx => "ipx",
            EtherAbbr::Netbui => "netbeui",
            EtherAbbr::Lat => "lat",
            EtherAbbr::Moprc => "moprc",
            EtherAbbr::Mopdl => "mopdl",
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, PartialEq)]
pub enum Direction {
    Src,
    Dst,
    SrcOrDst,
    SrcAndDst,
}

#[derive(Clone, Debug, PartialEq)]
pub enum WlanDirection {
    Ra,
    Ta,
    Addr1,
    Addr2,
    Addr3,
    Addr4,
}

impl AsRef<str> for Direction {
    fn as_ref(&self) -> &str {
        match self {
            Direction::Src => "src",
            Direction::Dst => "dst",
            Direction::SrcOrDst => "src or dst",
            Direction::SrcAndDst => "src and dst",
        }
    }
}

impl AsRef<str> for WlanDirection {
    fn as_ref(&self) -> &str {
        match self {
            WlanDirection::Ra => "ra",
            WlanDirection::Ta => "ta",
            WlanDirection::Addr1 => "addr1",
            WlanDirection::Addr2 => "addr2",
            WlanDirection::Addr3 => "addr3",
            WlanDirection::Addr4 => "add41",
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

/// Parent enum for al sub enums allowing for expressing all protocol types as a
/// [`Token`].
#[derive(Clone, Debug, PartialEq)]
enum Protocol {
    Iso(IsoProtocol),
    Ether(EtherProtocol),
    Primitive(NetProtocol),
}

#[derive(Clone, Debug, PartialEq)]
enum IsoProtocol {
    Clnp,
    Esis,
    Isis,
}

#[derive(Clone, Debug, PartialEq)]
enum EtherProtocol {
    Aarp,
    Arp,
    Atalk,
    Decnet,
    Ip,
    Ip6,
    Ipx,
    Iso,
    Lat,
    Loopback,
    Mopdl,
    Moprc,
    Netbeui,
    Rarp,
    Sca,
    Stp,
}

#[derive(Clone, Debug, PartialEq)]
enum NetProtocol {
    Icmp,
    Icmp6,
    Igmp,
    Igrp,
    Pim,
    Ah,
    Esp,
    Vrrp,
    Udp,
    Tcp,
}

impl AsRef<str> for Protocol {
    fn as_ref(&self) -> &str {
        match self {
            Protocol::Iso(proto) => proto.as_ref(),
            Protocol::Ether(proto) => proto.as_ref(),
            Protocol::Primitive(proto) => proto.as_ref(),
        }
    }
}

impl AsRef<str> for IsoProtocol {
    fn as_ref(&self) -> &str {
        match self {
            IsoProtocol::Clnp => "clnp",
            IsoProtocol::Esis => "esis",
            IsoProtocol::Isis => "isis",
        }
    }
}

impl AsRef<str> for EtherProtocol {
    fn as_ref(&self) -> &str {
        match self {
            EtherProtocol::Aarp => "aarp",
            EtherProtocol::Arp => "arp",
            EtherProtocol::Atalk => "atalk",
            EtherProtocol::Decnet => "decnet",
            EtherProtocol::Ip => "ip",
            EtherProtocol::Ip6 => "ip6",
            EtherProtocol::Ipx => "ipx",
            EtherProtocol::Iso => "iso",
            EtherProtocol::Lat => "lat",
            EtherProtocol::Loopback => "loopback",
            EtherProtocol::Mopdl => "mopdl",
            EtherProtocol::Moprc => "moprc",
            EtherProtocol::Netbeui => "netbeui",
            EtherProtocol::Rarp => "rarp",
            EtherProtocol::Sca => "sca",
            EtherProtocol::Stp => "stp",
        }
    }
}

impl AsRef<str> for NetProtocol {
    fn as_ref(&self) -> &str {
        match self {
            NetProtocol::Icmp => "icmp",
            NetProtocol::Icmp6 => "icmp6",
            NetProtocol::Igmp => "igmp",
            NetProtocol::Igrp => "igrp",
            NetProtocol::Pim => "pim",
            NetProtocol::Ah => "ah",
            NetProtocol::Esp => "esp",
            NetProtocol::Vrrp => "vrrp",
            NetProtocol::Udp => "udp",
            NetProtocol::Tcp => "tcp",
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, PartialEq)]
pub enum Primitive {
    Gateway(IpAddr),

    // todo: handle special `net net/len` case
    Net(IpAddr, Option<Direction>),
    Netmask(IpAddr, NetMask),
    NetLen(IpAddr, usize),

    Port(u16, Option<QualifierDirection>),
    PortRange(Range<u16>, Option<QualifierDirection>),
    Less(usize),
    Greater(usize),

    IpProto(NetProtocol),
    Ip6Proto(NetProtocol),
    Proto(NetProtocol),
    Tcp,
    Udp,
    Icmp,

    IpProtoChain(NetProtocol),
    Ip6ProtoChain(NetProtocol),
    ProtoChain(NetProtocol),

    EtherBroadcast,
    IpBroadcast,
    EtherMulticast,
    IpMulticast,
    Ip6Multicast,

    EtherProto(EtherProtocol),

    // Abbreviations for: ether proto \protocol
    // where protocol is one of the above protocols.
    Ip,
    Ip6,
    Arp,
    Rarp,
    Atalk,
    Aarp,
    Decnet,
    Iso,
    Stp,
    Ipx,
    Netbeui,

    // abbreviations for: ether proto \protocol
    // where  protocol  is  one of the above protocols
    Lat,
    Moprc,
    Modpdl,

    DecnetHost(Host, Option<QualifierDirection>),

    Llc(Option<LlcType>),

    Inbound,
    Outbound,

    // aliases for each other
    Ifname(String),
    On(String),

    Rnr(usize),
    RuleNum(usize),

    Reason(ReasonCode),

    Rset(String),
    RuleSet(String),

    Srnr(usize),
    SubRuleNum(usize),

    Action(Action),

    WlanRa(Host),
    WlanTa(Host),
    WlanAddr1(Host),
    WlanAddr2(Host),
    WlanAddr3(Host),
    WlanAddr4(Host),

    WlanType(WlanType, Option<WlanSubType>),

    SubType(WlanSubType),

    Direction(Direction),

    Vlan(Option<usize>),

    Mpls(Option<usize>),

    Pppoed,

    Pppoes(Option<usize>),

    Geneve(Option<usize>),

    IsoProto(IsoProtocol),
    Clnp,
    Esis,
    Isis,

    L1,
    L2,
    Iih,
    Lsp,
    Snp,
    Csnp,
    Psnp,

    Vpi(usize),

    Vci(usize),

    Lane,

    Oamf4s,
    Oamf4e,
    Oamf4,
    Oam,

    Metac,

    Bcc,

    Sc,

    Ilmic,

    ConnectMsg,

    MetaConnect,

    // todo: requires users to manually build the expression string rather than building programmatic
    Comparison(Expression, RelOp, Expression),
}

impl ToString for Primitive {
    fn to_string(&self) -> String {
        match self {
            Primitive::Gateway(addr) => format!("gateway {}", addr.to_string()),
            Primitive::Net(addr, dir) => match dir {
                Some(dir) => String::from(format!("{} net {}", dir.as_ref(), addr.to_string())),
                None => String::from(format!("net {}", addr.to_string())),
            },
            Primitive::Netmask(addr, mask) => String::from(format!("net {} mask {}", addr.to_string(), mask)),
            Primitive::NetLen(addr, len) => String::from(format!("net{}/{}", addr.to_string(), len)),
            Primitive::Port(port, dir) => match dir {
                Some(dir) => String::from(format!("{} port {}", dir.as_ref(), port)),
                None => String::from(format!("port {}", port)),
            },
            Primitive::PortRange(range, dir) => match dir {
                Some(dir) => String::from(format!("{} portrange {}-{}", dir.as_ref(), range.start, range.end)),
                None => String::from(format!("portrange {}-{}", range.start, range.end)),
            },
            Primitive::Less(size) => String::from(format!("less {}", size)),
            Primitive::Greater(size) => String::from(format!("greater {}", size)),
            Primitive::IpProto(proto) => match proto {
                NetProtocol::Tcp | NetProtocol::Udp | NetProtocol::Icmp =>
                    String::from(format!("ip proto \\{}", proto.as_ref())),
                _ => String::from(format!("ip proto {}", proto.as_ref())),
            },
            Primitive::Ip6Proto(proto) => match proto {
                NetProtocol::Tcp | NetProtocol::Udp | NetProtocol::Icmp =>
                    String::from(format!("ip proto \\{}", proto.as_ref())),
                _ => String::from(format!("ip6 proto {}", proto.as_ref())),
            },
            Primitive::Proto(proto) => match proto {
                NetProtocol::Tcp | NetProtocol::Udp | NetProtocol::Icmp =>
                    String::from(format!("ip proto \\{}", proto.as_ref())),
                _ => String::from(format!("proto {}", proto.as_ref())),
            },
            Primitive::Tcp => "tcp".to_owned(),
            Primitive::Udp => "udp".to_owned(),
            Primitive::Icmp => "icmp".to_owned(),
            Primitive::IpProtoChain(proto) => match proto {
                NetProtocol::Tcp | NetProtocol::Udp | NetProtocol::Icmp =>
                    String::from(format!("ip protochain \\{}", proto.as_ref())),
                _ => String::from(format!("ip protochain {}", proto.as_ref())),
            },
            Primitive::Ip6ProtoChain(proto) => match proto {
                NetProtocol::Tcp | NetProtocol::Udp | NetProtocol::Icmp =>
                    String::from(format!("ip6 protochain \\{}", proto.as_ref())),
                _ => String::from(format!("ip6 protochain {}", proto.as_ref())),
            },
            Primitive::ProtoChain(proto) => match proto {
                NetProtocol::Tcp | NetProtocol::Udp | NetProtocol::Icmp =>
                    String::from(format!("protochain \\{}", proto.as_ref())),
                _ => String::from(format!("protochain {}", proto.as_ref())),
            },
            Primitive::EtherBroadcast => "ether broadcast".to_owned(),
            Primitive::IpBroadcast => "ip broadcast".to_owned(),
            Primitive::EtherMulticast => "ether multicast".to_owned(),
            Primitive::IpMulticast => "ip multicast".to_owned(),
            Primitive::Ip6Multicast => "ip6 multicast".to_owned(),
            Primitive::EtherProto(proto) => match proto {
                EtherProtocol::Loopback => String::from(format!("ether proto loopback")),
                _ => String::from(format!("ether proto \\{}", proto.as_ref())),
            },
            Primitive::Ip => "ip".to_owned(),
            Primitive::Ip6 => "ip6".to_owned(),
            Primitive::Arp => "arp".to_owned(),
            Primitive::Rarp => "rarp".to_owned(),
            Primitive::Atalk => "atalk".to_owned(),
            Primitive::Aarp => "aarp".to_owned(),
            Primitive::Decnet => "decnet".to_owned(),
            Primitive::Iso => "iso".to_owned(),
            Primitive::Stp => "stp".to_owned(),
            Primitive::Ipx => "ipz".to_owned(),
            Primitive::Netbeui => "netbeui".to_owned(),
            Primitive::Lat => "lat".to_owned(),
            Primitive::Moprc => "morpc".to_owned(),
            Primitive::Modpdl => "mopdl".to_owned(),
            Primitive::DecnetHost(host, dir) => match dir {
                Some(dir) => String::from(format!("decnet {} {}", dir.as_ref(), host)),
                None => String::from(format!("decnet host {}", host)),
            },
            Primitive::Llc(llc_type) => match llc_type {
                Some(llc) => String::from(format!("llc {}", llc.as_ref())),
                None => "llc".to_owned(),
            },
            Primitive::Inbound => "inbound".to_owned(),
            Primitive::Outbound => "outbound".to_owned(),
            Primitive::Ifname(name) => String::from(format!("ifname {}", name)),
            Primitive::On(name) => String::from(format!("on {}", name)),
            Primitive::Rnr(num) => String::from(format!("rnr {}", num)),
            Primitive::RuleNum(num) => String::from(format!("rulenum {}", num)),
            Primitive::Reason(code) => String::from(format!("code {}", code.as_ref())),
            Primitive::Rset(num) => String::from(format!("rset {}", num)),
            Primitive::RuleSet(num) => String::from(format!("ruleset {}", num)),
            Primitive::Srnr(num) => String::from(format!("srnr {}", num)),
            Primitive::SubRuleNum(num) => String::from(format!("subrulenum {}", num)),
            Primitive::Action(act) => String::from(format!("action {}", act.as_ref())),
            Primitive::WlanRa(ehost) => String::from(format!("wlan ra {}", ehost)),
            Primitive::WlanTa(ehost) => String::from(format!("wlan ta {}", ehost)),
            Primitive::WlanAddr1(ehost) => String::from(format!("wlan addr1 {}", ehost)),
            Primitive::WlanAddr2(ehost) => String::from(format!("wlan addr2 {}", ehost)),
            Primitive::WlanAddr3(ehost) => String::from(format!("wlan addr3 {}", ehost)),
            Primitive::WlanAddr4(ehost) => String::from(format!("wlan addr4 {}", ehost)),
            Primitive::WlanType(wlan_type, sub_type) => match sub_type {
                Some(sub) => String::from(format!("type {} subtype {}", wlan_type.as_ref(), sub.as_ref())),
                None => String::from(format!("type {}", wlan_type.as_ref())),
            },
            Primitive::SubType(sub_type) => String::from(format!("subtype {}", sub_type.as_ref())),
            Primitive::Direction(dir) => String::from(format!("dir {}", dir.as_ref())),
            Primitive::Vlan(id) => match id {
                Some(id) => String::from(format!("vlan {}", id)),
                None => "vlan".to_owned(),
            },
            Primitive::Mpls(num) => match num {
                Some(num) => String::from(format!("mpls {}", num)),
                None => "mpls".to_owned(),
            },
            Primitive::Pppoed => "pppoed".to_owned(),
            Primitive::Pppoes(id) => match id {
                Some(id) => String::from(format!("pppoes {}", id)),
                None => "pppoes".to_owned(),
            },
            Primitive::Geneve(vni) => match vni {
                Some(vni) => String::from(format!("geneve {}", vni)),
                None => "geneve".to_owned(),
            },
            Primitive::IsoProto(proto) => String::from(format!("iso proto \\{}", proto.as_ref())),
            Primitive::Clnp => "clnp".to_owned(),
            Primitive::Esis => "esis".to_owned(),
            Primitive::Isis => "isis".to_owned(),
            Primitive::L1 => "li".to_owned(),
            Primitive::L2 => "l2".to_owned(),
            Primitive::Iih => "iih".to_owned(),
            Primitive::Lsp => "lsp".to_owned(),
            Primitive::Snp => "snp".to_owned(),
            Primitive::Csnp => "csnp".to_owned(),
            Primitive::Psnp => "psnp".to_owned(),
            Primitive::Vpi(n) => String::from(format!("vpi {}", n)),
            Primitive::Vci(n) => String::from(format!("vci {}", n)),
            Primitive::Lane => "lane".to_owned(),
            Primitive::Oamf4s => "oamf4s".to_owned(),
            Primitive::Oamf4e => "oamf4e".to_owned(),
            Primitive::Oamf4 => "oamf4".to_owned(),
            Primitive::Oam => "oam".to_owned(),
            Primitive::Metac => "metac".to_owned(),
            Primitive::Bcc => "bcc".to_owned(),
            Primitive::Sc => "sc".to_owned(),
            Primitive::Ilmic => "ilmic".to_owned(),
            Primitive::ConnectMsg => "connectmsg".to_owned(),
            Primitive::MetaConnect => "metaconnect".to_owned(),
            // Primitive::Comparison(left, relop, right) => String::from(format!("{} {} {}", left.0, relop.as_ref(),
            // right.0)),
            Primitive::Comparison(left, relop, right) =>
                String::from(format!("{} {} {}", "EXPR", relop.as_ref(), "EXPR")),
        }
    }
}

impl TokenStream for Primitive {
    fn stream(self) -> Iter<Token> {
        match self {
            Primitive::Gateway(addr) => vec![Token::Qualifier(Qualifier::Gateway), Token::Id(Identifier::Addr(addr))].into_iter,
            Primitive::Net(addr, dir) => {
                let mut tokens = match dir {
                    Some(dir) => vec![Token::Qualifier(Qualifier::Dir(QualifierDirection::General(dir)))],
                    None => vec![],
                };

                tokens.push(Token::Qualifier(Qualifier::Net));
                tokens.push(Token::Id(Identifier::Addr(addr)));

                tokens
            }
            Primitive::Netmask(addr, mask) => vec![Token::Qualifier(Qualifier::Net), Token::Id(Identifier::Addr(addr)), Token::Qualifier(Qualifier::Mask), Token::Id(Identifier::NetMask(mask))],
            Primitive::NetLen(addr, len) => vec![Token::Qualifier(Qualifier::Net), Token::Id(Identifier::Addr(addr)), Token::Operator(BinOp::Divide), Token::Id(Identifier::Len(len))],
            Primitive::Port(port, dir) => {
                let mut tokens = match dir {
                    Some(dir) => vec![Token::Qualifier(Qualifier::Dir(dir))],
                    None => vec![],
                };

                tokens.push(Token::Qualifier(Qualifier::Port));
                tokens.push(Token::Id(Identifier::Port(port)));

                tokens
            }
            Primitive::PortRange(range, dir) => {
                let mut tokens = match dir {
                    Some(dir) => vec![Token::Qualifier(Qualifier::Dir(dir))],
                    None => vec![],
                };

                tokens.push(Token::Qualifier(Qualifier::PortRange));
                tokens.push(Token::Id(Identifier::RangeStart(range.start)));
                tokens.push(Token::Operator(BinOp::Minus));
                tokens.push(Token::Id(Identifier::RangeEnd(range.end)));

                tokens.iter()
            }
            Primitive::Less(len) => vec![Token::Qualifier(Qualifier::Less), Token::Id(Identifier::Len(len))],
            Primitive::Greater(len) => vec![Token::Qualifier(Qualifier::Greater), Token::Id(Identifier::Len(len))],
            Primitive::IpProto(proto) => vec![Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip)), Token::Id(Identifier::Protocol(Protocol::Primitive(proto)))],
            Primitive::Ip6Proto(proto) => vec![Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip6)), Token::Id(Identifier::Protocol(Protocol::Primitive(proto)))],
            Primitive::Proto(proto) => match proto {
                NetProtocol::Udp | NetProtocol::Tcp | NetProtocol::Icmp => vec![Token::Qualifier(Qualifier::ProtoRaw), Token::Escape, Token::Id(Identifier::Protocol(Protocol::Primitive(proto)))],
                _ => vec![Token::Qualifier(Qualifier::ProtoRaw), Token::Id(Identifier::Protocol(Protocol::Primitive(proto)))]
            },
            Primitive::Tcp => vec![Token::Qualifier(Qualifier::ProtoAbbr(ProtoAbbr::Tcp))],
            Primitive::Udp => vec![Token::Qualifier(Qualifier::ProtoAbbr(ProtoAbbr::Udp))],
            Primitive::Icmp => vec![Token::Qualifier(Qualifier::ProtoAbbr(ProtoAbbr::Icmp))],
            Primitive::IpProtoChain(proto) => vec![Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip6)), Token::Qualifier(Qualifier::ProtoChain), Token::Id(Identifier::Protocol(Protocol::Primitive(proto)))],
            Primitive::Ip6ProtoChain(proto) => vec![Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip6)), Token::Qualifier(Qualifier::ProtoChain), Token::Id(Identifier::Protocol(Protocol::Primitive(proto)))],
            Primitive::ProtoChain(proto) => vec![Token::Qualifier(Qualifier::ProtoChain), Token::Id(Identifier::Protocol(Protocol::Primitive(proto)))],
            Primitive::EtherBroadcast => vec![Token::Qualifier(Qualifier::Ether), Token::Qualifier(Qualifier::Broadcast)],
            Primitive::IpBroadcast => vec![Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip)), Token::Qualifier(Qualifier::Broadcast)],
            Primitive::EtherMulticast => vec![Token::Qualifier(Qualifier::Ether), Token::Qualifier(Qualifier::Multicast)],
            Primitive::IpMulticast => vec![Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip)), Token::Qualifier(Qualifier::Multicast)],
            Primitive::Ip6Multicast => vec![Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip6)), Token::Qualifier(Qualifier::Multicast)],
            Primitive::EtherProto(proto) => vec![Qualifier::Ether, Qualifier::ProtoRaw, Identifier::Protocol(Protocol::Ether(proto))],
            Primitive::Ip => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Ip))],
            Primitive::Ip6 => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Ip6))],
            Primitive::Arp => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Arp))],
            Primitive::Rarp => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Rarp))],
            Primitive::Atalk => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Atalk))],
            Primitive::Aarp => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Aarp))],
            Primitive::Decnet => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Decnet))],
            Primitive::Iso => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Iso))],
            Primitive::Stp => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Stp))],
            Primitive::Ipx => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Ipx))],
            Primitive::Netbeui => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Netbui))],
            Primitive::Lat => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Lat))],
            Primitive::Moprc => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Moprc))],
            Primitive::Modpdl => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Mopdl))],
            Primitive::DecnetHost(host, dir) => {
                let mut tokens = vec![Token::Qualifier(Qualifier::Decnet)];

                match dir {
                    Some(dir) => tokens.push(Token::Qualifier(Qualifier::Dir(dir))),
                    None => tokens.push(Token::Qualifier(Qualifier::Host))
                }

                tokens.push(Token::Id(Identifier::Host(host)));

                tokens
            }
            Primitive::Llc(llc) => match llc {
                Some(llc) => vec![Token::Qualifier(Qualifier::Llc), Token::Id(Identifier::Llc(llc))],
                None => vec![Token::Qualifier(Qualifier::Llc)],
            }
            Primitive::Inbound => vec![Token::Qualifier(Qualifier::Inbound)],
            Primitive::Outbound => vec![Token::Qualifier(Qualifier::Outbound)],
            Primitive::Ifname(name) => vec![Token::Qualifier(Qualifier::Ifname), Token::Id(Identifier::Interface(name))],
            Primitive::On(name) => vec![Token::Qualifier(Qualifier::Ifname), Token::Id(Identifier::Interface(name))],
            Primitive::Rnr(rule_num) => vec![Token::Qualifier(Qualifier::Rnr), Token::Id(Identifier::RuleNum(rule_num))],
            Primitive::RuleNum(rule_num) => vec![Token::Qualifier(Qualifier::RuleNum), Token::Id(Identifier::RuleNum(rule_num))],
            Primitive::Reason(code) => vec![Token::Qualifier(Qualifier::Reason), Token::Id(Identifier::Code(code))],
            Primitive::Rset(name) => vec![Token::Qualifier(Qualifier::Rset), Token::Id(Identifier::RuleSet(name))],
            Primitive::RuleSet(name) => vec![Token::Qualifier(Qualifier::RuleSet), Token::Id(Identifier::RuleSet(name))],
            Primitive::Srnr(rule_num) => vec![Token::Qualifier(Qualifier::Srnr), Token::Id(Identifier::RuleNum(rule_num))],
            Primitive::SubRuleNum(rule_num) => vec![Token::Qualifier(Qualifier::SubRuleNum), Token::Id(Identifier::RuleNum(rule_num))],
            Primitive::Action(action) => vec![Token::Qualifier(Qualifier::Action), Token::Id(Identifier::Action(action))],
            Primitive::WlanRa(ehost) => vec![Token::Qualifier(Qualifier::Wlan), Token::Qualifier(Qualifier::Ra), Token::Id(Identifier::Host(ehost))],
            Primitive::WlanTa(ehost) => vec![Token::Qualifier(Qualifier::Wlan), Token::Qualifier(Qualifier::Ta), Token::Id(Identifier::Host(ehost))],
            Primitive::WlanAddr1(ehost) => vec![Token::Qualifier(Qualifier::Wlan), Token::Qualifier(Qualifier::Addr1), Token::Id(Identifier::Host(ehost))],
            Primitive::WlanAddr2(ehost) => vec![Token::Qualifier(Qualifier::Wlan), Token::Qualifier(Qualifier::Addr2), Token::Id(Identifier::Host(ehost))],
            Primitive::WlanAddr3(ehost) => vec![Token::Qualifier(Qualifier::Wlan), Token::Qualifier(Qualifier::Addr3), Token::Id(Identifier::Host(ehost))],
            Primitive::WlanAddr4(ehost) => vec![Token::Qualifier(Qualifier::Wlan), Token::Qualifier(Qualifier::Addr4), Token::Id(Identifier::Host(ehost))],
            Primitive::WlanType(wlan_type, sub_type) => {
                let mut tokens = vec![Token::Qualifier(Qualifier::WlanType), Token::Id(Identifier::WlanType(wlan_type))];

                if let Some(sub) = sub_type {
                    tokens.push(Token::Qualifier(Qualifier::WlanSubType));
                    tokens.push(Token::Id(Identifier::WlanSubType(sub)));
                }

                tokens
            }
            Primitive::SubType(sub_type) => vec![Token::Qualifier(Qualifier::WlanSubType), Token::Id(Identifier::WlanSubType(sub_type))],
            Primitive::Direction(dir) => vec![Token::Qualifier(Qualifier::RawDir), Token::Id(Identifier::Dir(dir))],
            Primitive::Vlan(id) => {
                let mut tokens = vec![Token::Qualifier(Qualifier::Vlan)];

                if let Some(id) = id {
                    tokens.push(Token::Id(Identifier::VlanId(id)));
                }

                tokens
            }
            Primitive::Mpls(label) => {
                let mut tokens = vec![Token::Qualifier(Qualifier::Vlan)];

                if let Some(label) = label {
                    tokens.push(Token::Id(Identifier::LabelNum(label)));
                }

                tokens
            }
            Primitive::Pppoed => vec![Token::Qualifier(Qualifier::PppOverEtherDiscovery)],
            Primitive::Pppoes(session_id) => {
                let mut tokens = vec![Token::Qualifier(Qualifier::Vlan)];

                if let Some(id) = session_id {
                    tokens.push(Token::Id(Identifier::SessionId(id)));
                }

                tokens
            }
            Primitive::Geneve(vni) => {
                let mut tokens = vec![Token::Qualifier(Qualifier::Geneve)];

                if let Some(id) = vni {
                    tokens.push(Token::Id(Identifier::VirtualNetworkIdentifier(id)));
                }

                tokens
            }
            Primitive::IsoProto(proto) => vec![Token::Qualifier(Qualifier::Iso), Token::Operator(BinOp::Divide), Token::Id(Identifier::Protocol(Protocol::Iso(proto)))],
            Primitive::Clnp => vec![Token::Qualifier(Qualifier::IsoAbbr(IsoProtocol::Clnp))],
            Primitive::Esis => vec![Token::Qualifier(Qualifier::IsoAbbr(IsoProtocol::Esis))],
            Primitive::Isis => vec![Token::Qualifier(Qualifier::IsoAbbr(IsoProtocol::Isis))],
            Primitive::L1 => vec![Token::Qualifier(Qualifier::L1)],
            Primitive::L2 => vec![Token::Qualifier(Qualifier::L2)].iter(),
            Primitive::Iih => vec![Token::Qualifier(Qualifier::Iih)].iter(),
            Primitive::Lsp => vec![Token::Qualifier(Qualifier::Lsp)].iter(),
            Primitive::Snp => vec![Token::Qualifier(Qualifier::Snp)].iter(),
            Primitive::Csnp => vec![Token::Qualifier(Qualifier::Csnp)].iter(),
            Primitive::Psnp => vec![Token::Qualifier(Qualifier::Psnp)].iter(),
            Primitive::Vpi(vpi) => vec![Token::Qualifier(Qualifier::VirtualPathIdentifier), Token::Id(Identifier::VirtualPathIdentifier(vpi))].iter(),
            Primitive::Vci(vci) => vec![Token::Qualifier(Qualifier::VirtualChannelIdentifier), Token::Id(Identifier::VirtualChannelIdentifier(vci))].iter(),
            Primitive::Lane => vec![Token::Qualifier(Qualifier::Lane)].iter(),
            Primitive::Oamf4s => vec![Token::Qualifier(Qualifier::Oamf4s)].iter(),
            Primitive::Oamf4e => vec![Token::Qualifier(Qualifier::Oamf4e)].iter(),
            Primitive::Oamf4 => vec![Token::Qualifier(Qualifier::Oamf4)].iter(),
            Primitive::Oam => vec![Token::Qualifier(Qualifier::Oam)].iter(),
            Primitive::Metac => vec![Token::Qualifier(Qualifier::MetaSignallingCircuit)].iter(),
            Primitive::Bcc => vec![Token::Qualifier(Qualifier::BroadcastSignalingCircuit)].iter(),
            Primitive::Sc => vec![Token::Qualifier(Qualifier::SignallingCircuit)].iter(),
            Primitive::Ilmic => vec![Token::Qualifier(Qualifier::IlmiCircuit)].iter(),
            Primitive::ConnectMsg => vec![Token::Qualifier(Qualifier::ConnectMsg)].iter(),
            Primitive::MetaConnect => vec![Token::Qualifier(Qualifier::MetaConnect)].iter(),
            Primitive::Comparison(left, op, right) => {
                left.stream()
                    .chain(iter::once(Token::RelationalOperator(op)))
                    .chain(right.stream())
            },
        }
    }
}