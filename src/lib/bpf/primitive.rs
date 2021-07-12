use std::iter::FromIterator;
use std::net::IpAddr;
use std::ops::Range;

use crate::bpf::expression::{BinOp, Expression};
use crate::bpf::token::{Token, TokenStream};

// todo: use something like https://docs.rs/strum/0.20.0/strum/index.html to generate enum names as str

// todo: needs better NetMask type
#[derive(Clone, Debug, PartialEq)]
pub struct NetMask(pub IpAddr);

#[derive(Clone, Debug, PartialEq)]
pub struct Host(pub String);

///////////////////////////////////////////////////////////////////////////////

/// Any token which is not a qualifier or other keyword.
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
    Dir(FrameDirection),
    VlanId(usize),
    LabelNum(usize),
    SessionId(usize),
    VirtualNetworkIdentifier(usize),
    VirtualPathIdentifier(usize),
    VirtualChannelIdentifier(usize),
}

impl ToString for Identifier {
    fn to_string(&self) -> String {
        match self {
            Identifier::Addr(addr) => addr.to_string(),
            Identifier::Host(host) => host.0.to_string(),
            Identifier::NetMask(mask) => mask.0.to_string(),
            Identifier::Port(port) => port.to_string(),
            Identifier::RangeStart(start) => start.to_string(),
            Identifier::RangeEnd(end) => end.to_string(),
            Identifier::Llc(llc) => llc.as_ref().to_owned(),
            Identifier::Len(len) => len.to_string(),
            Identifier::Protocol(proto) => proto.as_ref().to_owned(),
            Identifier::Interface(interface) => String::from(interface),
            Identifier::RuleNum(num) => num.to_string(),
            Identifier::RuleSet(name) => String::from(name),
            Identifier::Code(code) => code.as_ref().to_owned(),
            Identifier::Action(act) => act.as_ref().to_owned(),
            Identifier::WlanType(wlan) => wlan.as_ref().to_owned(),
            Identifier::WlanSubType(sub) => sub.as_ref().to_owned(),
            Identifier::Dir(dir) => dir.as_ref().to_owned(),
            Identifier::VlanId(id) => id.to_string(),
            Identifier::LabelNum(num) => num.to_string(),
            Identifier::SessionId(id) => id.to_string(),
            Identifier::VirtualNetworkIdentifier(id) => id.to_string(),
            Identifier::VirtualPathIdentifier(id) => id.to_string(),
            Identifier::VirtualChannelIdentifier(id) => id.to_string(),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, PartialEq)]
pub enum LlcType {
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
pub enum WlanType {
    Mgt,
    Ctl,
    Data,
}

#[derive(Clone, Debug, PartialEq)]
pub enum WlanSubType {
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
    Ne,
}

impl AsRef<str> for RelOp {
    fn as_ref(&self) -> &str {
        match self {
            RelOp::Gt => ">",
            RelOp::Lt => "<",
            RelOp::Gte => ">=",
            RelOp::Lte => "<=",
            RelOp::Eq => "=",
            RelOp::Ne => "!=",
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

    Ip6,

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
pub enum QualifierType {
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
pub enum QualifierDirection {
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
            Qualifier::Ip6 => "ip6",
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
    Icmp6,
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
            ProtoAbbr::Icmp6 => "icmp6",
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
            EtherAbbr::Stp => "stp",
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

#[derive(Clone, Debug, PartialEq)]
pub enum FrameDirection {
    Nods,
    Tods,
    Fromds,
    Dstods,
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

impl AsRef<str> for FrameDirection {
    fn as_ref(&self) -> &str {
        match self {
            FrameDirection::Nods => "nods",
            FrameDirection::Tods => "tods",
            FrameDirection::Fromds => "fromds",
            FrameDirection::Dstods => "dstods",
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

/// Parent enum for al sub enums allowing for expressing all protocol types as a
/// [`Token`].
#[derive(Clone, Debug, PartialEq)]
pub enum Protocol {
    Iso(IsoProtocol),
    Ether(EtherProtocol),
    Primitive(NetProtocol),
}

#[derive(Clone, Debug, PartialEq)]
pub enum IsoProtocol {
    Clnp,
    Esis,
    Isis,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EtherProtocol {
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
pub enum NetProtocol {
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
    Host(Host, Option<Direction>),
    Gateway(IpAddr),

    Net(IpAddr, Option<Direction>),
    Netmask(IpAddr, NetMask),
    NetLen(IpAddr, usize),

    Port(u16, Option<Direction>),
    PortRange(Range<u16>, Option<Direction>),
    Less(usize),
    Greater(usize),

    IpProto(NetProtocol),
    Ip6Proto(NetProtocol),
    Proto(NetProtocol),
    Tcp,
    Udp,
    Icmp,
    Icmp6,

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
    Mopdl,

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

    Direction(FrameDirection),

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

impl Primitive {
    pub fn abbreviated(&self) -> Option<Primitive> {
        match self {
            Primitive::Proto(proto) => match proto {
                NetProtocol::Tcp => Some(Primitive::Tcp),
                NetProtocol::Udp => Some(Primitive::Udp),
                NetProtocol::Icmp => Some(Primitive::Icmp),
                _ => None,
            },
            Primitive::EtherProto(proto) => match proto {
                EtherProtocol::Ip => Some(Primitive::Ip),
                EtherProtocol::Ip6 => Some(Primitive::Ip6),
                EtherProtocol::Arp => Some(Primitive::Arp),
                EtherProtocol::Rarp => Some(Primitive::Rarp),
                EtherProtocol::Atalk => Some(Primitive::Atalk),
                EtherProtocol::Aarp => Some(Primitive::Aarp),
                EtherProtocol::Decnet => Some(Primitive::Decnet),
                EtherProtocol::Iso => Some(Primitive::Iso),
                EtherProtocol::Stp => Some(Primitive::Stp),
                EtherProtocol::Ipx => Some(Primitive::Ipx),
                EtherProtocol::Netbeui => Some(Primitive::Netbeui),
                EtherProtocol::Lat => Some(Primitive::Lat),
                EtherProtocol::Moprc => Some(Primitive::Moprc),
                EtherProtocol::Mopdl => Some(Primitive::Mopdl),
                _ => None,
            },
            Primitive::IsoProto(proto) => match proto {
                IsoProtocol::Clnp => Some(Primitive::Clnp),
                IsoProtocol::Esis => Some(Primitive::Esis),
                IsoProtocol::Isis => Some(Primitive::Isis),
            },
            _ => None,
        }
    }

    pub fn verbose(&self) -> Option<Primitive> {
        match self {
            Primitive::Tcp => Some(Primitive::Proto(NetProtocol::Tcp)),
            Primitive::Udp => Some(Primitive::Proto(NetProtocol::Udp)),
            Primitive::Icmp => Some(Primitive::Proto(NetProtocol::Icmp)),

            Primitive::Ip => Some(Primitive::EtherProto(EtherProtocol::Ip)),
            Primitive::Ip6 => Some(Primitive::EtherProto(EtherProtocol::Ip6)),
            Primitive::Arp => Some(Primitive::EtherProto(EtherProtocol::Arp)),
            Primitive::Rarp => Some(Primitive::EtherProto(EtherProtocol::Rarp)),
            Primitive::Atalk => Some(Primitive::EtherProto(EtherProtocol::Atalk)),
            Primitive::Aarp => Some(Primitive::EtherProto(EtherProtocol::Aarp)),
            Primitive::Decnet => Some(Primitive::EtherProto(EtherProtocol::Decnet)),
            Primitive::Iso => Some(Primitive::EtherProto(EtherProtocol::Iso)),
            Primitive::Stp => Some(Primitive::EtherProto(EtherProtocol::Stp)),
            Primitive::Ipx => Some(Primitive::EtherProto(EtherProtocol::Ipx)),
            Primitive::Netbeui => Some(Primitive::EtherProto(EtherProtocol::Netbeui)),
            Primitive::Lat => Some(Primitive::EtherProto(EtherProtocol::Lat)),
            Primitive::Moprc => Some(Primitive::EtherProto(EtherProtocol::Moprc)),
            Primitive::Mopdl => Some(Primitive::EtherProto(EtherProtocol::Mopdl)),

            Primitive::Clnp => Some(Primitive::IsoProto(IsoProtocol::Clnp)),
            Primitive::Esis => Some(Primitive::IsoProto(IsoProtocol::Esis)),
            Primitive::Isis => Some(Primitive::IsoProto(IsoProtocol::Isis)),

            _ => None,
        }
    }
}

impl Into<TokenStream> for Primitive {
    fn into(self) -> TokenStream {
        let tokens = match self {
            Primitive::Host(host, dir) => {
                let mut tokens = match dir {
                    Some(dir) => vec![
                        Token::Qualifier(Qualifier::Dir(QualifierDirection::General(dir))),
                        Token::Qualifier(Qualifier::Host),
                    ],
                    None => vec![Token::Qualifier(Qualifier::Host)],
                };

                tokens.push(Token::Id(Identifier::Host(host)));

                tokens
            },
            Primitive::Gateway(addr) => vec![Token::Qualifier(Qualifier::Gateway), Token::Id(Identifier::Addr(addr))],
            Primitive::Net(addr, dir) => {
                let mut tokens = match dir {
                    Some(dir) => vec![Token::Qualifier(Qualifier::Dir(QualifierDirection::General(dir)))],
                    None => vec![],
                };

                tokens.push(Token::Qualifier(Qualifier::Net));
                tokens.push(Token::Id(Identifier::Addr(addr)));

                tokens
            },
            Primitive::Netmask(addr, mask) => vec![
                Token::Qualifier(Qualifier::Net),
                Token::Id(Identifier::Addr(addr)),
                Token::Qualifier(Qualifier::Mask),
                Token::Id(Identifier::NetMask(mask)),
            ],
            Primitive::NetLen(addr, len) => vec![
                Token::Qualifier(Qualifier::Net),
                Token::Id(Identifier::Addr(addr)),
                Token::Operator(BinOp::Divide),
                Token::Id(Identifier::Len(len)),
            ],
            Primitive::Port(port, dir) => {
                let mut tokens = match dir {
                    Some(dir) => vec![Token::Qualifier(Qualifier::Dir(QualifierDirection::General(dir)))],
                    None => vec![],
                };

                tokens.push(Token::Qualifier(Qualifier::Port));
                tokens.push(Token::Id(Identifier::Port(port)));

                tokens
            },
            Primitive::PortRange(range, dir) => {
                let mut tokens = match dir {
                    Some(dir) => vec![Token::Qualifier(Qualifier::Dir(QualifierDirection::General(dir)))],
                    None => vec![],
                };

                tokens.push(Token::Qualifier(Qualifier::PortRange));
                tokens.push(Token::Id(Identifier::RangeStart(range.start)));
                tokens.push(Token::Operator(BinOp::Minus));
                tokens.push(Token::Id(Identifier::RangeEnd(range.end)));

                tokens
            },
            Primitive::Less(len) => vec![Token::Qualifier(Qualifier::Less), Token::Id(Identifier::Len(len))],
            Primitive::Greater(len) => vec![Token::Qualifier(Qualifier::Greater), Token::Id(Identifier::Len(len))],
            Primitive::IpProto(proto) => vec![
                Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip)),
                Token::Id(Identifier::Protocol(Protocol::Primitive(proto))),
            ],
            Primitive::Ip6Proto(proto) => vec![
                Token::Qualifier(Qualifier::Ip6),
                Token::Qualifier(Qualifier::ProtoRaw),
                Token::Id(Identifier::Protocol(Protocol::Primitive(proto))),
            ],
            Primitive::Proto(proto) => match proto {
                NetProtocol::Udp | NetProtocol::Tcp | NetProtocol::Icmp => vec![
                    Token::Qualifier(Qualifier::ProtoRaw),
                    Token::Escape,
                    Token::Id(Identifier::Protocol(Protocol::Primitive(proto))),
                ],
                _ => vec![
                    Token::Qualifier(Qualifier::ProtoRaw),
                    Token::Id(Identifier::Protocol(Protocol::Primitive(proto))),
                ],
            },
            Primitive::Tcp => vec![Token::Qualifier(Qualifier::ProtoAbbr(ProtoAbbr::Tcp))],
            Primitive::Udp => vec![Token::Qualifier(Qualifier::ProtoAbbr(ProtoAbbr::Udp))],
            Primitive::Icmp => vec![Token::Qualifier(Qualifier::ProtoAbbr(ProtoAbbr::Icmp))],
            Primitive::Icmp6 => vec![Token::Qualifier(Qualifier::ProtoAbbr(ProtoAbbr::Icmp6))],
            Primitive::IpProtoChain(proto) => vec![
                Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip6)),
                Token::Qualifier(Qualifier::ProtoChain),
                Token::Id(Identifier::Protocol(Protocol::Primitive(proto))),
            ],
            Primitive::Ip6ProtoChain(proto) => vec![
                Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip6)),
                Token::Qualifier(Qualifier::ProtoChain),
                Token::Id(Identifier::Protocol(Protocol::Primitive(proto))),
            ],
            Primitive::ProtoChain(proto) => vec![
                Token::Qualifier(Qualifier::ProtoChain),
                Token::Id(Identifier::Protocol(Protocol::Primitive(proto))),
            ],
            Primitive::EtherBroadcast => vec![
                Token::Qualifier(Qualifier::Ether),
                Token::Qualifier(Qualifier::Broadcast),
            ],
            Primitive::IpBroadcast => vec![
                Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip)),
                Token::Qualifier(Qualifier::Broadcast),
            ],
            Primitive::EtherMulticast => vec![
                Token::Qualifier(Qualifier::Ether),
                Token::Qualifier(Qualifier::Multicast),
            ],
            Primitive::IpMulticast => vec![
                Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip)),
                Token::Qualifier(Qualifier::Multicast),
            ],
            Primitive::Ip6Multicast => vec![
                Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ip6)),
                Token::Qualifier(Qualifier::Multicast),
            ],
            Primitive::EtherProto(proto) => {
                let mut tokens = vec![
                    Token::Qualifier(Qualifier::Ether),
                    Token::Qualifier(Qualifier::ProtoRaw),
                ];

                if proto != EtherProtocol::Loopback {
                    tokens.push(Token::Escape);
                }

                tokens.push(Token::Id(Identifier::Protocol(Protocol::Ether(proto))));

                tokens
            },
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
            Primitive::Mopdl => vec![Token::Qualifier(Qualifier::EtherAbbr(EtherAbbr::Mopdl))],
            Primitive::DecnetHost(host, dir) => {
                let mut tokens = vec![Token::Qualifier(Qualifier::Decnet)];

                match dir {
                    Some(dir) => tokens.push(Token::Qualifier(Qualifier::Dir(dir))),
                    None => tokens.push(Token::Qualifier(Qualifier::Host)),
                }

                tokens.push(Token::Id(Identifier::Host(host)));

                tokens
            },
            Primitive::Llc(llc) => match llc {
                Some(llc) => vec![Token::Qualifier(Qualifier::Llc), Token::Id(Identifier::Llc(llc))],
                None => vec![Token::Qualifier(Qualifier::Llc)],
            },
            Primitive::Inbound => vec![Token::Qualifier(Qualifier::Inbound)],
            Primitive::Outbound => vec![Token::Qualifier(Qualifier::Outbound)],
            Primitive::Ifname(name) => vec![
                Token::Qualifier(Qualifier::Ifname),
                Token::Id(Identifier::Interface(name)),
            ],
            Primitive::On(name) => vec![
                Token::Qualifier(Qualifier::Ifname),
                Token::Id(Identifier::Interface(name)),
            ],
            Primitive::Rnr(rule_num) => vec![
                Token::Qualifier(Qualifier::Rnr),
                Token::Id(Identifier::RuleNum(rule_num)),
            ],
            Primitive::RuleNum(rule_num) => vec![
                Token::Qualifier(Qualifier::RuleNum),
                Token::Id(Identifier::RuleNum(rule_num)),
            ],
            Primitive::Reason(code) => vec![Token::Qualifier(Qualifier::Reason), Token::Id(Identifier::Code(code))],
            Primitive::Rset(name) => vec![Token::Qualifier(Qualifier::Rset), Token::Id(Identifier::RuleSet(name))],
            Primitive::RuleSet(name) => vec![
                Token::Qualifier(Qualifier::RuleSet),
                Token::Id(Identifier::RuleSet(name)),
            ],
            Primitive::Srnr(rule_num) => vec![
                Token::Qualifier(Qualifier::Srnr),
                Token::Id(Identifier::RuleNum(rule_num)),
            ],
            Primitive::SubRuleNum(rule_num) => vec![
                Token::Qualifier(Qualifier::SubRuleNum),
                Token::Id(Identifier::RuleNum(rule_num)),
            ],
            Primitive::Action(action) => vec![
                Token::Qualifier(Qualifier::Action),
                Token::Id(Identifier::Action(action)),
            ],
            Primitive::WlanRa(ehost) => vec![
                Token::Qualifier(Qualifier::Wlan),
                Token::Qualifier(Qualifier::Ra),
                Token::Id(Identifier::Host(ehost)),
            ],
            Primitive::WlanTa(ehost) => vec![
                Token::Qualifier(Qualifier::Wlan),
                Token::Qualifier(Qualifier::Ta),
                Token::Id(Identifier::Host(ehost)),
            ],
            Primitive::WlanAddr1(ehost) => vec![
                Token::Qualifier(Qualifier::Wlan),
                Token::Qualifier(Qualifier::Addr1),
                Token::Id(Identifier::Host(ehost)),
            ],
            Primitive::WlanAddr2(ehost) => vec![
                Token::Qualifier(Qualifier::Wlan),
                Token::Qualifier(Qualifier::Addr2),
                Token::Id(Identifier::Host(ehost)),
            ],
            Primitive::WlanAddr3(ehost) => vec![
                Token::Qualifier(Qualifier::Wlan),
                Token::Qualifier(Qualifier::Addr3),
                Token::Id(Identifier::Host(ehost)),
            ],
            Primitive::WlanAddr4(ehost) => vec![
                Token::Qualifier(Qualifier::Wlan),
                Token::Qualifier(Qualifier::Addr4),
                Token::Id(Identifier::Host(ehost)),
            ],
            Primitive::WlanType(wlan_type, sub_type) => {
                let mut tokens = vec![
                    Token::Qualifier(Qualifier::WlanType),
                    Token::Id(Identifier::WlanType(wlan_type)),
                ];

                if let Some(sub) = sub_type {
                    tokens.push(Token::Qualifier(Qualifier::WlanSubType));
                    tokens.push(Token::Id(Identifier::WlanSubType(sub)));
                }

                tokens
            },
            Primitive::SubType(sub_type) => vec![
                Token::Qualifier(Qualifier::WlanSubType),
                Token::Id(Identifier::WlanSubType(sub_type)),
            ],
            Primitive::Direction(dir) => vec![Token::Qualifier(Qualifier::RawDir), Token::Id(Identifier::Dir(dir))],
            Primitive::Vlan(id) => {
                let mut tokens = vec![Token::Qualifier(Qualifier::Vlan)];

                if let Some(id) = id {
                    tokens.push(Token::Id(Identifier::VlanId(id)));
                }

                tokens
            },
            Primitive::Mpls(label) => {
                let mut tokens = vec![Token::Qualifier(Qualifier::Vlan)];

                if let Some(label) = label {
                    tokens.push(Token::Id(Identifier::LabelNum(label)));
                }

                tokens
            },
            Primitive::Pppoed => vec![Token::Qualifier(Qualifier::PppOverEtherDiscovery)],
            Primitive::Pppoes(session_id) => {
                let mut tokens = vec![Token::Qualifier(Qualifier::Vlan)];

                if let Some(id) = session_id {
                    tokens.push(Token::Id(Identifier::SessionId(id)));
                }

                tokens
            },
            Primitive::Geneve(vni) => {
                let mut tokens = vec![Token::Qualifier(Qualifier::Geneve)];

                if let Some(id) = vni {
                    tokens.push(Token::Id(Identifier::VirtualNetworkIdentifier(id)));
                }

                tokens
            },
            Primitive::IsoProto(proto) => vec![
                Token::Qualifier(Qualifier::Iso),
                Token::Qualifier(Qualifier::ProtoRaw),
                Token::Escape,
                Token::Id(Identifier::Protocol(Protocol::Iso(proto))),
            ],
            Primitive::Clnp => vec![Token::Qualifier(Qualifier::IsoAbbr(IsoProtocol::Clnp))],
            Primitive::Esis => vec![Token::Qualifier(Qualifier::IsoAbbr(IsoProtocol::Esis))],
            Primitive::Isis => vec![Token::Qualifier(Qualifier::IsoAbbr(IsoProtocol::Isis))],
            Primitive::L1 => vec![Token::Qualifier(Qualifier::L1)],
            Primitive::L2 => vec![Token::Qualifier(Qualifier::L2)],
            Primitive::Iih => vec![Token::Qualifier(Qualifier::Iih)],
            Primitive::Lsp => vec![Token::Qualifier(Qualifier::Lsp)],
            Primitive::Snp => vec![Token::Qualifier(Qualifier::Snp)],
            Primitive::Csnp => vec![Token::Qualifier(Qualifier::Csnp)],
            Primitive::Psnp => vec![Token::Qualifier(Qualifier::Psnp)],
            Primitive::Vpi(vpi) => vec![
                Token::Qualifier(Qualifier::VirtualPathIdentifier),
                Token::Id(Identifier::VirtualPathIdentifier(vpi)),
            ],
            Primitive::Vci(vci) => vec![
                Token::Qualifier(Qualifier::VirtualChannelIdentifier),
                Token::Id(Identifier::VirtualChannelIdentifier(vci)),
            ],
            Primitive::Lane => vec![Token::Qualifier(Qualifier::Lane)],
            Primitive::Oamf4s => vec![Token::Qualifier(Qualifier::Oamf4s)],
            Primitive::Oamf4e => vec![Token::Qualifier(Qualifier::Oamf4e)],
            Primitive::Oamf4 => vec![Token::Qualifier(Qualifier::Oamf4)],
            Primitive::Oam => vec![Token::Qualifier(Qualifier::Oam)],
            Primitive::Metac => vec![Token::Qualifier(Qualifier::MetaSignallingCircuit)],
            Primitive::Bcc => vec![Token::Qualifier(Qualifier::BroadcastSignalingCircuit)],
            Primitive::Sc => vec![Token::Qualifier(Qualifier::SignallingCircuit)],
            Primitive::Ilmic => vec![Token::Qualifier(Qualifier::IlmiCircuit)],
            Primitive::ConnectMsg => vec![Token::Qualifier(Qualifier::ConnectMsg)],
            Primitive::MetaConnect => vec![Token::Qualifier(Qualifier::MetaConnect)],
            Primitive::Comparison(left, op, right) => Into::<TokenStream>::into(left)
                .into_iter()
                .chain(std::iter::once(Token::RelationalOperator(op)))
                .chain(Into::<TokenStream>::into(right).into_iter())
                .collect(),
        };

        TokenStream::from_iter(tokens)
    }
}
