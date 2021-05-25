use crate::bpf::primitive::{Primitive, Qualifier};
use crate::bpf::token::{Token, TokenStream, TokenStreamIntoIter, TokenStreamIterator};

/// Used to control the verbosity of some primitives when an expression is
/// built.
pub enum PrimitiveVerbosity {
    /// Use the exact [`Primitive`] variant.
    Exact,

    /// Use the most verbose [`Primitive`] variant possible (eq `proto \tcp`
    /// instead of `tcp`).
    Verbose,

    /// Use the most concise [`Primitive`] variant possible (eq `tcp` instead of
    /// `proto \tcp`).
    Brief,
}

/// Allows for specifying how a [`FilterBuilder`] will serialize the
/// [`FilterExpression`].
pub struct FilterOptions {
    /// Use symbols for primitive expressions rather than their word
    /// counterparts, defaults to `false`.
    ///
    /// # Example
    /// ```
    /// use netbug::bpf::filter::{FilterOptions, FilterBuilder, FilterExpression};
    /// use netbug::bpf::primitive::Primitive;
    ///
    /// let options = FilterOptions::new();
    /// let mut builder = FilterBuilder::with(Primitive::Udp, &options)
    ///     .or(Primitive::Tcp);
    ///
    /// assert_eq!(builder.build(), FilterExpression::new("udp or tcp".to_owned()));
    ///
    /// let mut options = FilterOptions::new();
    /// options.use_symbols(true);
    ///
    /// let builder = FilterBuilder::with(Primitive::Udp, &options)
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
    /// let options = FilterOptions::new();
    /// let builder = FilterBuilder::with(primitive.clone(), &options);
    ///
    /// assert_eq!(builder.build(), FilterExpression::new("(5 + 10) ^ 2 = 5".to_owned()));
    ///
    /// let mut options = FilterOptions::new();
    /// options.use_whitespace(false);
    ///
    /// let builder = FilterBuilder::with(primitive, &options);
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
    /// let options = FilterOptions::new();
    /// let builder = FilterBuilder::with(Primitive::Proto(NetProtocol::Udp), &options);
    ///
    /// assert_eq!(builder.build(), FilterExpression::new("proto \\udp".to_owned()));
    ///
    /// let mut options = FilterOptions::new();
    /// options.use_verbosity(PrimitiveVerbosity::Brief);
    ///
    /// let builder = FilterBuilder::with(Primitive::Proto(NetProtocol::Udp), &options);
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

    pub fn use_whitespace(&mut self, whitespace: bool) { self.whitespace = whitespace; }

    pub fn use_symbols(&mut self, symbols: bool) { self.symbol_operators = symbols; }

    pub fn use_verbosity(&mut self, verbosity: PrimitiveVerbosity) { self.verbosity = verbosity; }
}

/// Programatically build a [`FilterExpression`]. Some of the behavior of this
/// builder acn be configured using a [`FilterOptions`] object.
///
/// Take care when using any of [`FilterBuilder::and_filter`],
/// [`FilterBuilder::and_not_filter`], [`FilterBuilder::or_filter`], or
/// [`FilterBuilder::or_not_filter`] as different filters may have diffrent
/// [`FilterOptions`], and the resulting [`FilterExpression`] may be an odd
/// mixture of styles, so it is suggested that you create only one instance of
/// [`FilterOptions`] which you pass to all [`FilterBuilder`]s.
///
/// # Examples
/// ```
/// # use netbug::bpf::filter::{FilterOptions, PrimitiveVerbosity, FilterBuilder};
/// # use netbug::bpf::primitive::{Primitive, NetProtocol, Direction};
/// # let mut options = FilterOptions::new();
/// options.use_symbols(true);
/// options.use_verbosity(PrimitiveVerbosity::Brief);
/// let options = options;
///
/// let sub_filter = FilterBuilder::with(Primitive::Proto(NetProtocol::Udp), &options)
///     .or(Primitive::Inbound);
/// let filter = FilterBuilder::with_not(Primitive::Icmp, &options)
///     .or_filter(sub_filter)
///     .build();
///
/// assert_eq!(filter.to_string(), "! icmp || (udp || inbound)")
/// ```
pub struct FilterBuilder<'a> {
    options: &'a FilterOptions,

    tokens: TokenStream,
}

impl<'a> FilterBuilder<'a> {
    /// Create a basic [`FilterBuilder`] with the optional given
    /// [`FormatOptions`], if `options` is `None` the default values are used.
    fn new(options: &FilterOptions) -> FilterBuilder {
        FilterBuilder {
            options,
            tokens: TokenStream::new(),
        }
    }

    /// Construct a new [`FilterBuilder`] with the given [`Primitive`] as a
    /// starting point.
    pub fn with(primitive: Primitive, options: &FilterOptions) -> FilterBuilder {
        let mut builder = Self::new(options);

        builder.tokens.push_primitive(builder.format_primitive(primitive));

        builder
    }

    /// Same as [`FilterBuilder::with`] only negating the given [`Primitive`].
    pub fn with_not(primitive: Primitive, options: &FilterOptions) -> FilterBuilder {
        let mut builder = Self::new(options);

        builder.tokens.push(Token::Not);
        builder.tokens.push_primitive(builder.format_primitive(primitive));

        builder
    }

    /// Construct a new [`FilterBuilder`] with all the same primitives and
    /// [`FilterOptions`] as the given [`FilterBuilder`]. If the given filter
    /// has more than one primitive, the entire expression with be parenthesised
    /// before more primitives are added.
    pub fn with_filter(filter: FilterBuilder<'a>) -> FilterBuilder<'a> {
        let mut builder = FilterBuilder::new(filter.options);

        builder.push_stream(filter.into());

        builder
    }

    /// Same as [`FilterBuilder::with_filter`] only negating the filter
    /// expression.
    pub fn with_not_filter(filter: FilterBuilder<'a>) -> FilterBuilder<'a> {
        let mut builder = FilterBuilder::new(filter.options);

        builder.tokens.push(Token::Not);
        builder.push_stream(filter.into());

        builder
    }

    ///////////////////////////////////////////////////////////////////////////

    pub fn and(mut self, primitive: Primitive) -> FilterBuilder<'a> {
        self.tokens.push(Token::And);
        self.tokens.push_primitive(self.format_primitive(primitive));

        self
    }

    pub fn and_not(mut self, primitive: Primitive) -> FilterBuilder<'a> {
        self.tokens.push(Token::And);
        self.tokens.push(Token::Not);
        self.tokens.push_primitive(self.format_primitive(primitive));

        self
    }

    pub fn or(mut self, primitive: Primitive) -> FilterBuilder<'a> {
        self.tokens.push(Token::Or);
        self.tokens.push_primitive(self.format_primitive(primitive));

        self
    }

    pub fn or_not(mut self, primitive: Primitive) -> FilterBuilder<'a> {
        self.tokens.push(Token::Or);
        self.tokens.push(Token::Not);
        self.tokens.push_primitive(self.format_primitive(primitive));

        self
    }

    ///////////////////////////////////////////////////////////////////////////

    fn push_stream(&mut self, stream: TokenStream) {
        let parentheses = stream.len() > 1;

        if parentheses {
            self.tokens.push(Token::OpenParentheses);
        }

        stream.into_iter().for_each(|token| self.tokens.push(token));

        if parentheses {
            self.tokens.push(Token::CloseParentheses);
        }
    }

    pub fn and_filter(mut self, filter: FilterBuilder) -> FilterBuilder<'a> {
        self.tokens.push(Token::And);
        self.push_stream(filter.into());

        self
    }

    pub fn and_not_filter(mut self, filter: FilterBuilder) -> FilterBuilder<'a> {
        self.tokens.push(Token::And);
        self.tokens.push(Token::Not);
        self.push_stream(filter.into());

        self
    }

    pub fn or_filter(mut self, filter: FilterBuilder) -> FilterBuilder<'a> {
        self.tokens.push(Token::Or);
        self.push_stream(filter.into());

        self
    }

    pub fn or_not_filter(mut self, filter: FilterBuilder) -> FilterBuilder<'a> {
        self.tokens.push(Token::Or);
        self.tokens.push(Token::Not);
        self.push_stream(filter.into());

        self
    }

    ///////////////////////////////////////////////////////////////////////////

    fn format_primitive(&self, primitive: Primitive) -> Primitive {
        match self.options.verbosity {
            PrimitiveVerbosity::Exact => primitive,
            PrimitiveVerbosity::Verbose => match primitive.verbose() {
                Some(p) => p,
                None => primitive,
            },
            PrimitiveVerbosity::Brief => match primitive.abbreviated() {
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
                    Token::OpenBracket | Token::CloseParentheses => false,
                    _ => true,
                },
                _ => match next.unwrap() {
                    Token::CloseParentheses => false,
                    _ => true,
                },
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

impl Into<TokenStream> for FilterBuilder<'_> {
    fn into(self) -> TokenStream { self.tokens }
}

#[derive(Debug, PartialEq)]
pub struct FilterExpression(String);

impl FilterExpression {
    pub fn new(filter: String) -> FilterExpression { FilterExpression(filter) }
}

impl ToString for FilterExpression {
    fn to_string(&self) -> String { self.0.clone() }
}

#[cfg(test)]
mod test {
    use crate::bpf::expression::{Expression, ExpressionBuilder, Operand};
    use crate::bpf::filter::{FilterBuilder, FilterExpression, FilterOptions, PrimitiveVerbosity};
    use crate::bpf::primitive::{EtherProtocol, IsoProtocol, NetProtocol, Primitive, QualifierProtocol, RelOp};
    use crate::bpf::token::Token::RelationalOperator;

    ///////////////////////////////////////////////////////////////////////////

    #[test]
    fn test_abbreviated() {
        let mut options = FilterOptions::new();
        options.use_verbosity(PrimitiveVerbosity::Brief);

        let actual = FilterBuilder::with(Primitive::Proto(NetProtocol::Tcp), &options)
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

        let expected = FilterExpression(
            concat!(
                "tcp and udp and icmp and proto igmp ",
                "or ip and ip6 and arp and rarp and atalk and aarp and decnet and iso and stp and ipx and netbeui and \
                 lat and moprc and mopdl and ether proto loopback ",
                "or clnp and esis and isis"
            )
            .to_owned(),
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_verbose() {
        let mut options = FilterOptions::new();
        options.use_verbosity(PrimitiveVerbosity::Verbose);

        let actual = FilterBuilder::with(Primitive::Proto(NetProtocol::Tcp), &options)
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

        let expected = FilterExpression(
            concat!(
                "proto \\tcp and proto \\udp and proto \\icmp ",
                "or ether proto \\ip and ether proto \\ip6 and ether proto \\arp and ether proto \\rarp ",
                "and ether proto \\atalk and ether proto \\aarp and ether proto \\decnet ",
                "and ether proto \\iso and ether proto \\stp and ether proto \\ipx ",
                "and ether proto \\netbeui and ether proto \\lat and ether proto \\moprc ",
                "and ether proto \\mopdl ",
                "or iso proto \\clnp and iso proto \\esis and iso proto \\isis",
            )
            .to_owned(),
        );

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_exact() {
        let mut options = FilterOptions::new();
        options.use_verbosity(PrimitiveVerbosity::Exact);

        let actual = FilterBuilder::with(Primitive::Tcp, &options)
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
            ExpressionBuilder::new(Operand::Integer(10)).build(),
        );

        let options = FilterOptions::new();
        let builder = FilterBuilder::with(primitive, &options);

        let expected = FilterExpression::new("icmp[(5 >> 10):0] != 10".to_owned());

        assert_eq!(builder.build(), expected);
    }

    #[test]
    fn test_not() {
        let options = FilterOptions::new();
        let actual = FilterBuilder::with_not(Primitive::Tcp, &options)
            .or(Primitive::Udp)
            .or_not(Primitive::Icmp)
            .and_not(Primitive::Ip)
            .build();

        let expected = FilterExpression("not tcp or udp or not icmp and not ip".to_owned());

        assert_eq!(actual, expected)
    }

    #[test]
    fn test_sub_filter() {
        let options = FilterOptions::new();
        let sub = FilterBuilder::with(Primitive::Udp, &options).or(Primitive::Tcp);

        let actual = FilterBuilder::with(Primitive::Ip6, &options).and_filter(sub).build();
        let expected = FilterExpression("ip6 and (udp or tcp)".to_owned());

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_sub_filter_one_internal() {
        let options = FilterOptions::new();
        let sub = FilterBuilder::with(Primitive::Udp, &options);

        let actual = FilterBuilder::with(Primitive::Ip6, &options).and_filter(sub).build();
        let expected = FilterExpression("ip6 and udp".to_owned());

        assert_eq!(actual, expected);
    }
}
