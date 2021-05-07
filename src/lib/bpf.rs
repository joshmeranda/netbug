use std::net::IpAddr;
use std::ops::Range;
use std::collections::VecDeque;

// todo: needs better NetMask type
type NetMask = IpAddr;
type Host = String;

struct FilterBuilder {}

impl FilterBuilder {
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

enum QualifierType {
    Host,
    Net,
    Port,
    PortRange,
}

enum QualifierProtocol {
    Ether,
    Fddi,
    Tr,
    Wlan,
    Ip,
    Ip6,
    Aro,
    Rarp,
    Decnet,
    Tcp,
    Udp,
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
    Proto(QualifierProtocol),
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

    IpProto(QualifierProtocol),
    Ip6Proto(QualifierProtocol),
    Proto(QualifierProtocol),
    Tcp,
    Udp,
    Icmp,

    IpProtoChain(QualifierProtocol),
    Ip6ProtoChain(QualifierProtocol),
    ProtoChain(QualifierProtocol),

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

enum Operand {
    Integer(usize),

    PacketData(QualifierProtocol, usize, usize)
}

enum BinOp {
    Plus,
    Minus,
    Multiply,
    Divide,
    Modulus,
    And,
    Or,
    Exponent,
    LeftShift,
    RightShift,
}

struct ExpressionBuilder {
    operands: VecDeque<Operand>,

    operators: VecDeque<BinOp>
}

impl ExpressionBuilder {
    pub fn new() -> ExpressionBuilder{
        ExpressionBuilder {
            operands: VecDeque::new(),
            operators: VecDeque::new(),
        }
    }

    pub fn operand(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push_front(operand);
        self
    }

    pub fn number(mut self, n: usize) -> ExpressionBuilder {
        let operand = Operand::Integer(n);
        self.operands.push_front(operand);
        self
    }

    pub fn packet_data(mut self, proto: QualifierProtocol, offset: usize, size: usize) -> ExpressionBuilder {
        let operand = Operand::PacketData(proto, offset, size);
        self.operands.push_front(operand);
        self
    }

    pub fn operator(mut self, operator: BinOp) -> ExpressionBuilder {
        self.operators.push_front(operator);
        self
    }

    pub fn plus(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Plus)
    }

    pub fn minus(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Minus)
    }

    pub fn multiply(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Multiply)
    }

    pub fn divide(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Divide)
    }

    pub fn modulus(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Modulus)
    }

    pub fn and(mut self) -> ExpressionBuilder {
        self.operator(BinOp::And)
    }

    pub fn or(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Or)
    }

    pub fn exponent(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Exponent)
    }

    pub fn left_shift(mut self) -> ExpressionBuilder {
        self.operator(BinOp::LeftShift)
    }

    pub fn right_shift(mut self) -> ExpressionBuilder {
        self.operator(BinOp::RightShift)
    }
}