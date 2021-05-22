use crate::bpf::primitive::{Primitive, Qualifier};
use crate::bpf::token::{Token, TokenStream, TokenStreamIntoIter, TokenStreamIterator};

pub enum PrimitiveVerbosity {
    Exact,
    Long,
    Short,
}

/// Allows for specifying how a [`FilterBuilder`] should behave.
pub struct FilterOptions {
    /// Use symbols for primitive expressions rather than their word
    /// counterparts, defaults to `false`.
    /// # Example
    /// ```
    /// use netbug::bpf::filter::{FilterOptions, FilterBuilder, FilterExpression};
    /// use netbug::bpf::primitive::Primitive;
    ///
    /// let mut builder = FilterBuilder::with(Primitive::Udp, None)
    ///     .or(Primitive::Tcp);
    ///
    /// assert_eq!(builder.build(), FilterExpression::new("udp or tcp".to_owned()));
    ///
    /// let mut options = FilterOptions::new();
    /// options.use_symbols(true);
    ///
    /// let builder = FilterBuilder::with(Primitive::Udp, Some(options))
    ///     .or(Primitive::Tcp);
    ///
    /// assert_eq!(builder.build(), FilterExpression::new("udp || tcp".to_owned()));
    /// ```
    pub symbol_operators: bool,

    /// Use whitespace to separate operands from operators when serializing
    /// arithmetic expression. Defaults to `true`.
    ///
    /// # Example
    /// ```
    /// # use netbug::bpf::filter::{FilterOptions, FilterBuilder, FilterExpression};
    /// # use netbug::bpf::primitive::{Primitive, RelOp};
    /// # use netbug::bpf::expression::{ExpressionBuilder, Operand};
    ///
    /// let inner_expression = ExpressionBuilder::new(Operand::Integer(5))
    ///     .plus(Operand::Integer(10))
    ///     .build();
    ///
    /// let primitive = Primitive::Comparison(
    ///     ExpressionBuilder::from_expr(inner_expression).raise(Operand::Integer(2)).build(),
    ///     RelOp::Eq,
    ///     ExpressionBuilder::new(Operand::Integer(5)).build());
    ///
    /// let builder = FilterBuilder::with(primitive.clone(), None);
    ///
    /// assert_eq!(builder.build(), FilterExpression::new("(5 + 10) ^ 2 = 5".to_owned()));
    ///
    /// let mut options = FilterOptions::new();
    /// options.use_whitespace(false);
    ///
    /// let builder = FilterBuilder::with(primitive, Some(options));
    ///
    /// assert_eq!(builder.build(), FilterExpression::new(String::from("(5+10)^2=5")));
    /// ```
    pub whitespace: bool,

    /// Specifies whether to use a [`Qualifier`]'s more verbose or abbreviated
    /// variant if available, or follow the users exact specification. Defaults
    /// to [`QualifierVariant::Exact`].
    ///
    /// # Example
    /// ```
    /// # use netbug::bpf::filter::{FilterBuilder, FilterExpression, FilterOptions, PrimitiveVerbosity};
    /// # use netbug::bpf::primitive::{Primitive, NetProtocol};
    /// let builder = FilterBuilder::with(Primitive::Proto(NetProtocol::Udp), None);
    ///
    /// assert_eq!(builder.build(), FilterExpression::new("proto \\udp".to_owned()));
    ///
    /// let mut options = FilterOptions::new();
    /// options.use_verbosity(PrimitiveVerbosity::Short);
    ///
    /// let builder = FilterBuilder::with(Primitive::Proto(NetProtocol::Udp), Some(options));
    ///
    /// assert_eq!(builder.build(), FilterExpression::new("udp".to_owned()));
    /// ```
    pub verbosity: PrimitiveVerbosity,
}

impl FilterOptions {

    /// Create a new [`FilterOptions`] object with the default value.
    pub fn new() -> FilterOptions {
        Self {
            whitespace:       true,
            symbol_operators: false,
            verbosity:        PrimitiveVerbosity::Exact,
        }
    }

    pub fn use_whitespace(&mut self, whitespace: bool) {
        self.whitespace = whitespace;
    }

    pub fn use_symbols(&mut self, symbols: bool) {
        self.symbol_operators = symbols;
    }

    pub fn use_verbosity(&mut self, verbosity: PrimitiveVerbosity) {
        self.verbosity = verbosity;
    }
}

pub struct FilterBuilder {
    options: FilterOptions,
    tokens:  TokenStream,
}

impl FilterBuilder {
    /// Create a basic [`FilterBuilder`] with the optional given [`FormatOptions`], if `options` is `None` the default values are used.
    fn new(options: Option<FilterOptions>) -> FilterBuilder {
        FilterBuilder {
            options: match options {
                Some(opt) => opt,
                None => FilterOptions::new()
            },
            tokens:  TokenStream::new(),
        }
    }

    pub fn with(primitive: Primitive, options: Option<FilterOptions>) -> FilterBuilder {
        let mut builder = Self::new(options);

        builder.tokens.push_primitive(builder.format_primitive(primitive));

        builder
    }

    pub fn with_not(primitive: Primitive, options: Option<FilterOptions>) -> FilterBuilder {
        let mut builder = Self::new(options);

        builder.tokens.push(Token::Not);
        builder.tokens.push_primitive(builder.format_primitive(primitive));

        builder
    }

    pub fn and(mut self, primitive: Primitive) -> FilterBuilder {
        self.tokens.push(Token::And);
        self.tokens.push_primitive(self.format_primitive(primitive));

        self
    }

    pub fn and_not(mut self, primitive: Primitive) -> FilterBuilder {
        self.tokens.push(Token::And);
        self.tokens.push(Token::Not);
        self.tokens.push_primitive(self.format_primitive(primitive));

        self
    }

    pub fn or(mut self, primitive: Primitive) -> FilterBuilder {
        self.tokens.push(Token::Or);
        self.tokens.push_primitive(self.format_primitive(primitive));

        self
    }

    pub fn or_not(mut self, primitive: Primitive) -> FilterBuilder {
        self.tokens.push(Token::Or);
        self.tokens.push(Token::Not);
        self.tokens.push_primitive(self.format_primitive(primitive));

        self
    }

    fn format_primitive(&self, primitive: Primitive) -> Primitive {
        match self.options.verbosity {
            PrimitiveVerbosity::Exact => primitive,
            PrimitiveVerbosity::Long => match primitive.verbose() {
                Some(p) => p,
                None => primitive,
            },
            PrimitiveVerbosity::Short => match primitive.abbreviated() {
                Some(p) => p,
                None => primitive,
            },
        }
    }

    /// Determine if a space is needed after a given [`Token`] given the value
    /// of the next [`Token`].
    fn needs_trailing_space(&self, token: &Token, next: Option<&Token>) -> bool {
        if next.is_none() {
            return false;
        }

        match token {
            Token::CloseParentheses | Token::CloseBracket | Token::Operator(_) => match next.unwrap() {
                Token::Operator(_) | Token::Integer(_) => self.options.whitespace,
                Token::CloseParentheses | Token::Colon => false,
                _ => true,
            },
            Token::OpenParentheses | Token::OpenBracket | Token::Colon | Token::Escape => false,
            Token::And | Token::Or | Token::Not | Token::Id(_) => true,
            Token::Integer(_) => match next.unwrap() {
                Token::CloseParentheses | Token::CloseBracket => false,
                _ => {
                    println!("=== Number: {}", self.options.whitespace);
                    self.options.whitespace
                },
            },
            Token::RelationalOperator(_) => self.options.whitespace,
            Token::Qualifier(qualifier) => match qualifier {
                Qualifier::Proto(_) => match next.unwrap() {
                    // the special case of a packet data access expression
                    Token::OpenBracket => false,
                    _ => true,
                },
                _ => true,
            },
        }
    }

    pub fn build(&self) -> FilterExpression {
        let mut filter = String::new();
        let mut iter: TokenStreamIterator = (&self.tokens).into_iter();

        let mut next = iter.next();

        while let Some(token) = next {
            filter.push_str(token.repr(&self.options).as_str());

            next = iter.next();

            if self.needs_trailing_space(token, next) {
                filter.push(' ');
            }
        }

        FilterExpression(filter)
    }
}

#[derive(Debug, PartialEq)]
pub struct FilterExpression(String);

impl FilterExpression {
    pub fn new(filter: String) -> FilterExpression {
        FilterExpression(filter)
    }
}

// todo: testing
//   check each of the FormatOptions
//   check the packet access

#[cfg(test)]
mod test {
    use crate::bpf::filter::{FilterBuilder, FilterExpression, FilterOptions, PrimitiveVerbosity};
    use crate::bpf::primitive::{Primitive, QualifierProtocol, RelOp, NetProtocol, EtherProtocol, IsoProtocol};
    use crate::bpf::expression::{ExpressionBuilder, Operand, Expression};
    use crate::bpf::token::Token::RelationalOperator;

    ///////////////////////////////////////////////////////////////////////////

    #[test]
    fn test_abbreviated() {
        let mut options = FilterOptions::new();
        options.use_verbosity(PrimitiveVerbosity::Short);

        let actual = FilterBuilder::with(Primitive::Proto(NetProtocol::Tcp), Some(options))
            .and(Primitive::Proto(NetProtocol::Udp))
            .and(Primitive::Proto(NetProtocol::Icmp))
            .and(Primitive::Proto(NetProtocol::Igmp)) // should not be shortened

            .or(Primitive::EtherProto(EtherProtocol::Ip))
            .and(Primitive::EtherProto(EtherProtocol::Ip6))
            .and(Primitive::EtherProto(EtherProtocol::Arp))
            .and(Primitive::EtherProto(EtherProtocol::Rarp))
            .and(Primitive::EtherProto(EtherProtocol::Atalk))
            .and(Primitive::EtherProto(EtherProtocol::Aarp))
            .and(Primitive::EtherProto(EtherProtocol::Decnet))
            .and(Primitive::EtherProto(EtherProtocol::Iso))
            .and(Primitive::EtherProto(EtherProtocol::Stp))
            .and(Primitive::EtherProto(EtherProtocol::Ipx))
            .and(Primitive::EtherProto(EtherProtocol::Netbeui))
            .and(Primitive::EtherProto(EtherProtocol::Lat))
            .and(Primitive::EtherProto(EtherProtocol::Moprc))
            .and(Primitive::EtherProto(EtherProtocol::Mopdl))
            .and(Primitive::EtherProto(EtherProtocol::Loopback)) // should not be shortened

            .or(Primitive::IsoProto(IsoProtocol::Clnp))
            .and(Primitive::IsoProto(IsoProtocol::Esis))
            .and(Primitive::IsoProto(IsoProtocol::Isis))
            .build();

        let expected = FilterExpression(concat!("tcp and udp and icmp and proto igmp ",
                "or ip and ip6 and arp and rarp and atalk and aarp and decnet and iso and stp and ipx and netbeui and lat and moprc and mopdl and ether proto loopback ",
                "or clnp and esis and isis").to_owned());

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_verbose() {
        let mut options = FilterOptions::new();
        options.use_verbosity(PrimitiveVerbosity::Long);

        let actual = FilterBuilder::with(Primitive::Proto(NetProtocol::Tcp), Some(options))
            .and(Primitive::Udp)
            .and(Primitive::Icmp)

            .or(Primitive::Ip)
            .and(Primitive::Ip6)
            .and(Primitive::Arp)
            .and(Primitive::Rarp)
            .and(Primitive::Atalk)
            .and(Primitive::Aarp)
            .and(Primitive::Decnet)
            .and(Primitive::Iso)
            .and(Primitive::Stp)
            .and(Primitive::Ipx)
            .and(Primitive::Netbeui)
            .and(Primitive::Lat)
            .and(Primitive::Moprc)
            .and(Primitive::Mopdl)

            .or(Primitive::Clnp)
            .and(Primitive::Esis)
            .and(Primitive::Isis)
            .build();

        let expected = FilterExpression(concat!(
            "proto \\tcp and proto \\udp and proto \\icmp ",
            "or ether proto \\ip and ether proto \\ip6 and ether proto \\arp and ether proto \\rarp ",
            "and ether proto \\atalk and ether proto \\aarp and ether proto \\decnet ",
            "and ether proto \\iso and ether proto \\stp and ether proto \\ipx ",
            "and ether proto \\netbeui and ether proto \\lat and ether proto \\moprc ",
            "and ether proto \\mopdl ",
            "or iso proto \\clnp and iso proto \\esis and iso proto \\isis",
        ).to_owned());

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_exact() {
        let mut options = FilterOptions::new();
        options.use_verbosity(PrimitiveVerbosity::Exact);

        let actual = FilterBuilder::with(Primitive::Tcp, Some(options))
            .and(Primitive::Proto(NetProtocol::Tcp))
            .build();
        let expected = FilterExpression::new("tcp and proto \\tcp".to_owned());

        assert_eq!(actual, expected);
    }

    ///////////////////////////////////////////////////////////////////////////

    #[test]
    fn test_packet_access() {
        let inner_expression = ExpressionBuilder::new(Operand::Integer(5))
            .right_shift(Operand::Integer(10))
            .build();

        let primitive = Primitive::Comparison(
            ExpressionBuilder::new(Operand::PacketData(QualifierProtocol::Icmp, inner_expression, 0)).build(),
            RelOp::Ne,
            ExpressionBuilder::new(Operand::Integer(10)).build());

        let builder = FilterBuilder::with(primitive, None);

        let expected = FilterExpression::new("icmp[(5 >> 10):0] != 10".to_owned());

        assert_eq!(builder.build(), expected);
    }
}