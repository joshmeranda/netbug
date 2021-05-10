use crate::bpf::primitive::{Primitive, Qualifier};
use crate::bpf::Token;

struct FilterOptions {
    /// Use whitespace to separate operands from operators when serializing
    /// arithmetic expression. If `true`, '(5+10)^2` will be serialized as
    /// `(5 + 10) ^ 2`. Defaults to `true`.
    whitespace: bool,

    /// Use symbols for primitive expressions rather than their word
    /// counterparts, defaults to false:
    /// - "or" -> "||"
    /// - "and" -> "&&"
    /// - "not" -> "!"
    symbol_operators: bool,

    /// Always use full primitives rather than their abbreviations. For example,
    /// `proto \tcp` over `tcp`. If `false`, the output will be exactly what is
    /// added.
    verbose_proto: bool,
}

struct FilterBuilder {
    options: FilterOptions,
    tokens:  Vec<Token>,
}

impl FilterBuilder {
    pub fn with(primitive: Primitive) -> FilterBuilder {}

    pub fn with_not(primitive: Primitive) -> FilterBuilder {}

    fn add_primitive(&mut self, primitive: Primitive) {
        match primitive {
            Primitive::Gateway(host) => {
                self.tokens.push(Token::Qualifier(Qualifier::Gateway));
                self.tokens.push(Token::Host(host));
            },
            Primitive::Net(_, _) => {},
            Primitive::Netmask(_, _) => {},
            Primitive::NetLen(_, _) => {},
            Primitive::Port(_, _) => {},
            Primitive::PortRange(_, _) => {},
            Primitive::Less(_) => {},
            Primitive::Greater(_) => {},
            Primitive::IpProto(_) => {},
            Primitive::Ip6Proto(_) => {},
            Primitive::Proto(_) => {},
            Primitive::Tcp => {},
            Primitive::Udp => {},
            Primitive::Icmp => {},
            Primitive::IpProtoChain(_) => {},
            Primitive::Ip6ProtoChain(_) => {},
            Primitive::ProtoChain(_) => {},
            Primitive::EtherBroadcast => {},
            Primitive::IpBroadcast => {},
            Primitive::EtherMulticast => {},
            Primitive::IpMulticast => {},
            Primitive::Ip6Multicast => {},
            Primitive::EtherProto(_) => {},
            Primitive::Ip => {},
            Primitive::Ip6 => {},
            Primitive::Arp => {},
            Primitive::Rarp => {},
            Primitive::Atalk => {},
            Primitive::Aarp => {},
            Primitive::Decnet => {},
            Primitive::Iso => {},
            Primitive::Stp => {},
            Primitive::Ipz => {},
            Primitive::Netbeui => {},
            Primitive::Lat => {},
            Primitive::Moprc => {},
            Primitive::Modpdl => {},
            Primitive::DecnetHost(_, _) => {},
            Primitive::Llc(_) => {},
            Primitive::Inbound => {},
            Primitive::Outbound => {},
            Primitive::Ifname(_) => {},
            Primitive::On(_) => {},
            Primitive::Rnr(_) => {},
            Primitive::RuleNum(_) => {},
            Primitive::Reason(_) => {},
            Primitive::Rset(_) => {},
            Primitive::RuleSet(_) => {},
            Primitive::Srnr(_) => {},
            Primitive::SubRuleNum(_) => {},
            Primitive::Action(_) => {},
            Primitive::WlanRa(_) => {},
            Primitive::WlanTa(_) => {},
            Primitive::WlanAddr1(_) => {},
            Primitive::WlanAddr2(_) => {},
            Primitive::WlanAddr3(_) => {},
            Primitive::WlanAddr4(_) => {},
            Primitive::WlanType(_, _) => {},
            Primitive::SubType(_) => {},
            Primitive::Direction(_) => {},
            Primitive::Vlan(_) => {},
            Primitive::Mpls(_) => {},
            Primitive::Pppoed => {},
            Primitive::Pppoes(_) => {},
            Primitive::Geneve(_) => {},
            Primitive::IsoProto(_) => {},
            Primitive::Clnp => {},
            Primitive::Esis => {},
            Primitive::Isis => {},
            Primitive::L1 => {},
            Primitive::L2 => {},
            Primitive::Iih => {},
            Primitive::Lsp => {},
            Primitive::Snp => {},
            Primitive::Csnp => {},
            Primitive::Psnp => {},
            Primitive::Vpi(_) => {},
            Primitive::Vci(_) => {},
            Primitive::Lane => {},
            Primitive::Oamf4s => {},
            Primitive::Oamf4e => {},
            Primitive::Oamf4 => {},
            Primitive::Oam => {},
            Primitive::Metac => {},
            Primitive::Bcc => {},
            Primitive::Sc => {},
            Primitive::Ilmic => {},
            Primitive::ConnectMsg => {},
            Primitive::MetaConnect => {},
            Primitive::Comparison(_, _, _) => {},
        }
    }

    pub fn and(mut self, primitive: Primitive) -> FilterBuilder { self }

    pub fn and_not(mut self, primitive: Primitive) -> FilterBuilder { self }

    pub fn or(mut self, primitive: Primitive) -> FilterBuilder { self }

    pub fn or_not(mut self, primitive: Primitive) -> FilterBuilder { self }
}
