use std::net::IpAddr;
use std::ops::Range;

// todo: needs better NetMask type
type NetMask = IpAddr;
type Host = String;

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

enum QualifierType {
    Host,
    Net,
    Port,
    PortRange,
}

pub enum Protocol {
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

impl AsRef<str> for Protocol {
    fn as_ref(&self) -> &str {
        match self {
            Protocol::Ether => "ether",
            Protocol::Fddi => "fddi",
            Protocol::Tr => "tr",
            Protocol::Wlan => "wlan",
            Protocol::Ip => "ip",
            Protocol::Ip6 => "ip6",
            Protocol::Arp => "arp",
            Protocol::Rarp => "rarp",
            Protocol::Decnet => "decent",
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
        }
    }
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

enum Qualifier {
    Type(QualifierType),
    Dir(QualifierDirection),
    Proto(Protocol),
}

enum LlcType {
    I,
    S,
    U,
    R,
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

enum ReasonCode {
    Match,
    BadOffset,
    Fragment,
    Short,
    Normalize,
    Memory,
}

enum Action {
    Pass,
    Block,
    Nat,
    Rdr,
    Binat,
    Scrub
}

enum WlanType {
    Mgt,
    Ctl,
    Data
}

enum WlanSubType {
    // mgt
    AssocReq, AssocResp, ReAssocReq, ReAssocResp, ProbeResp, Beacon, Atim, DisAssoc, Auth, DeAuth,

    // ctl
    PsPoll, Rts, Cts, Ack, CfEnd, CfEndAck,

    // data
    Data, DataCfAck, DataCfPoll, DataCfAckPoll, Null, CfAck, CfPoll, CfAckPoll, QosData, QosDataCfPoll, QosDataCfAckPoll, Qos, QosCfPoll, QosCfAckPoll,
}

enum IsoProtocol {
    Clnp,
    Esis,
    Isis
}

enum PrimitiveId{
    Broadcast,
    Multicast,
    Else(String),
}

enum RelOp {
    Gt,
    Lt,
    Gte,
    Lte,
    Eq,
    Neq,
}

enum Primitive {
    Generic(Vec<Qualifier>, PrimitiveId),
    Gateway(String),

    // todo: handle special `net net/len` case
    Net(IpAddr, Option<NetMask>),
    Port(QualifierDirection, u16),
    PortRange(QualifierDirection, Range<u16>),
    Less(String),
    Greater(String),

    IpProto(Protocol),
    Ip6Proto(Protocol),
    Proto(Protocol),
    Tcp,
    Udp,
    Icmp,

    IpProtoChain(Protocol),
    Ip6ProtoChain(Protocol),
    ProtoChain(Protocol),

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

    DecnetHost(QualifierDirection, Host),

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

    WlanType(WlanType, WlanSubType),

    SubType(WlanSubType),

    Direction(QualifierDirection),

    Vlan(Option<usize>),

    Mpls(Option<usize>),

    Pppoed,

    Pppoes(Option<String>),

    Geneve(Option<usize>),

    IsoProto(IsoProtocol),
    Clnp, Esis, Isis,

    L1, L2, Iih, Lsp, Snp, Csnp, Psnp,

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
    Comparison(String),
}