use std::net::IpAddr;
use std::ops::Range;

use crate::bpf::expression::Expression;

// todo: use something like https://docs.rs/strum/0.20.0/strum/index.html to generate enum names as str

// todo: needs better NetMask type
type NetMask = IpAddr;
type Host = String;

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

///////////////////////////////////////////////////////////////////////////////

enum ReasonCode {
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

enum Action {
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

enum WlanType {
    Mgt,
    Ctl,
    Data,
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

enum Qualifier {
    Type(QualifierType),
    Dir(QualifierDirection),
    Proto(QualifierProtocol),
}

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
    Ip,
    Ip6,
    Arp,
    Rarp,
    Decnet,
    Tcp,
    Udp,
}

enum QualifierDirection {
    Src,
    Dst,
    SrcOrDst,
    SrcAndDst,
    Ra,
    Ta,
    Addr1,
    Addr2,
    Addr3,
    Addr4,
}

impl AsRef<str> for Qualifier {
    fn as_ref(&self) -> &str {
        match self {
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
            QualifierDirection::Src => "src",
            QualifierDirection::Dst => "dst",
            QualifierDirection::SrcOrDst => "src or dst",
            QualifierDirection::SrcAndDst => "src and dst",
            QualifierDirection::Ra => "ra",
            QualifierDirection::Ta => "ta",
            QualifierDirection::Addr1 => "addr1",
            QualifierDirection::Addr2 => "addr2",
            QualifierDirection::Addr3 => "addr3",
            QualifierDirection::Addr4 => "addr4",
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
        }
    }
}

///////////////////////////////////////////////////////////////////////////////

/// Parent enum for al sub enums allowing for expressing all protocol types as a [`Token`].
enum Protocol {
    Iso(IsoProtocol),
    Ether(EtherProtocol),
    Primitive(NetProtocol),
}

enum IsoProtocol {
    Clnp,
    Esis,
    Isis,
}

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
            Protocol::Qualifier(proto) => proto.as_ref(),
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

pub enum Primitive {
    Gateway(IpAddr),

    // todo: handle special `net net/len` case
    Net(IpAddr, Option<QualifierDirection>),
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
    Ipz,
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

    Direction(QualifierDirection),

    Vlan(Option<usize>),

    Mpls(Option<usize>),

    Pppoed,

    Pppoes(Option<String>),

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
            Primitive::Generic(qualifiers, id) => {
                let mut s = qualifiers.iter().fold(String::new(), |mut acc, q| {
                    acc.push_str(q.as_ref());
                    acc.push(' ');

                    acc
                });

                s.push_str(id.as_ref());

                s
            },
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
            Primitive::Ipz => "ipz".to_owned(),
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
