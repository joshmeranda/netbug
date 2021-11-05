use crate::bpf::primitive::{Primitive, Qualifier};
use crate::bpf::token::{Token, TokenStream, TokenStreamIterator};

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
    /// let mut builder = FilterBuilder::with(Primitive::Udp, &options);
    /// builder.or(Primitive::Tcp);
    ///
    /// let expr = builder.build();
    ///
    /// assert_eq!(expr.to_string(), "udp or tcp");
    ///
    /// let mut options = FilterOptions::new();
    /// options.use_symbols(true);
    ///
    /// let mut builder = FilterBuilder::with(Primitive::Udp, &options);
    /// builder.or(Primitive::Tcp);
    ///
    /// let expr = builder.build();
    ///
    /// assert_eq!(expr.to_string(), "udp || tcp");
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
    /// let mut inner_builder = ExpressionBuilder::new(Operand::Integer(5));
    /// inner_builder.plus(Operand::Integer(10));
    ///
    /// let inner_expr = inner_builder.build();
    ///
    /// let mut right_builder = ExpressionBuilder::from_expr(inner_expr);
    /// right_builder.raise(Operand::Integer(2));
    ///
    /// let left = right_builder.build();
    /// let right = ExpressionBuilder::new(Operand::Integer(5)).build();
    ///
    /// let primitive = Primitive::Comparison(left, RelOp::Eq, right);
    ///
    /// let options = FilterOptions::new();
    /// let expr = FilterBuilder::with(primitive.clone(), &options)
    ///     .build();
    ///
    /// assert_eq!(expr.to_string(), "(5 + 10) ^ 2 = 5");
    ///
    /// let mut options = FilterOptions::new();
    /// options.use_whitespace(false);
    ///
    /// let expr = FilterBuilder::with(primitive, &options)
    ///     .build();
    ///
    /// assert_eq!(expr.to_string(), "(5+10)^2=5");
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
    /// let expr = FilterBuilder::with(Primitive::Proto(NetProtocol::Udp), &options)
    ///     .build();
    ///
    /// assert_eq!(expr.to_string(), "proto \\udp");
    ///
    /// let mut options = FilterOptions::new();
    /// options.use_verbosity(PrimitiveVerbosity::Brief);
    ///
    /// let expr = FilterBuilder::with(Primitive::Proto(NetProtocol::Udp), &options)
    ///     .build();
    ///
    /// assert_eq!(expr.to_string(), "udp");
    /// ```
    pub verbosity: PrimitiveVerbosity,
}

impl FilterOptions {
    /// Create a new [`FilterOptions`] object with the default value.
    pub fn new() -> FilterOptions {
        Self::default()
    }

    pub fn use_whitespace(&mut self, whitespace: bool) { self.whitespace = whitespace; }

    pub fn use_symbols(&mut self, symbols: bool) { self.symbol_operators = symbols; }

    pub fn use_verbosity(&mut self, verbosity: PrimitiveVerbosity) { self.verbosity = verbosity; }
}

impl Default for FilterOptions {
    fn default() -> Self {
        Self {
            whitespace: true,
            symbol_operators: false,
            verbosity: PrimitiveVerbosity::Exact,
        }
    }
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
/// let mut sub_filter = FilterBuilder::with(Primitive::Proto(NetProtocol::Udp), &options);
/// sub_filter.or(Primitive::Inbound);
///
/// let mut builder = FilterBuilder::with_not(Primitive::Icmp, &options);
/// builder.or_filter(sub_filter);
///
/// let filter = builder.build();
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

    pub fn and(&mut self, primitive: Primitive) {
        self.tokens.push(Token::And);
        self.tokens.push_primitive(self.format_primitive(primitive));
    }

    pub fn and_not(&mut self, primitive: Primitive) {
        self.tokens.push(Token::And);
        self.tokens.push(Token::Not);
        self.tokens.push_primitive(self.format_primitive(primitive));
    }

    pub fn or(&mut self, primitive: Primitive) {
        self.tokens.push(Token::Or);
        self.tokens.push_primitive(self.format_primitive(primitive));
    }

    pub fn or_not(&mut self, primitive: Primitive) {
        self.tokens.push(Token::Or);
        self.tokens.push(Token::Not);
        self.tokens.push_primitive(self.format_primitive(primitive));
    }

    ///////////////////////////////////////////////////////////////////////////

    fn push_stream(&mut self, stream: TokenStream) {
        // todo: should be one primitive not one token
        let parentheses = stream.len() > 1;

        if parentheses {
            self.tokens.push(Token::OpenParentheses);
        }

        stream.into_iter().for_each(|token| self.tokens.push(token));

        if parentheses {
            self.tokens.push(Token::CloseParentheses);
        }
    }

    pub fn and_filter(&mut self, filter: FilterBuilder) {
        self.tokens.push(Token::And);
        self.push_stream(filter.into());
    }

    pub fn and_not_filter(&mut self, filter: FilterBuilder) {
        self.tokens.push(Token::And);
        self.tokens.push(Token::Not);
        self.push_stream(filter.into());
    }

    pub fn or_filter(&mut self, filter: FilterBuilder) {
        self.tokens.push(Token::Or);
        self.push_stream(filter.into());
    }

    pub fn or_not_filter(&mut self, filter: FilterBuilder) {
        self.tokens.push(Token::Or);
        self.tokens.push(Token::Not);
        self.push_stream(filter.into());
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
            Token::And | Token::Or | Token::Not => true,
            Token::Id(_) | Token::Integer(_) => match next.unwrap() {
                Token::CloseParentheses | Token::CloseBracket => false,
                _ => self.options.whitespace,
            },
            Token::RelationalOperator(_) => self.options.whitespace,
            Token::Qualifier(qualifier) => match qualifier {
                Qualifier::Proto(_) => !matches!(next.unwrap(), Token::OpenBracket | Token::CloseParentheses),
                _ => !matches!(next.unwrap(), Token::CloseParentheses),
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

impl From<FilterBuilder<'_>> for TokenStream {
    fn from(builder: FilterBuilder<'_>) -> Self {
        builder.tokens
    }
}

#[derive(Debug, Deserialize, PartialEq)]
pub struct FilterExpression(String);

impl FilterExpression {
    /// Create a simple empty [`FilterExpression`] which will match any packet.
    pub fn empty() -> FilterExpression { FilterExpression(String::from("")) }
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

        let mut builder = FilterBuilder::with(Primitive::Proto(NetProtocol::Tcp), &options);
        builder.and(Primitive::Proto(NetProtocol::Udp));
        builder.and(Primitive::Proto(NetProtocol::Icmp));
        builder.and(Primitive::Proto(NetProtocol::Igmp)); // should not be shortened
        builder.or(Primitive::EtherProto(EtherProtocol::Ip));
        builder.and(Primitive::EtherProto(EtherProtocol::Ip6));
        builder.and(Primitive::EtherProto(EtherProtocol::Arp));
        builder.and(Primitive::EtherProto(EtherProtocol::Rarp));
        builder.and(Primitive::EtherProto(EtherProtocol::Atalk));
        builder.and(Primitive::EtherProto(EtherProtocol::Aarp));
        builder.and(Primitive::EtherProto(EtherProtocol::Decnet));
        builder.and(Primitive::EtherProto(EtherProtocol::Iso));
        builder.and(Primitive::EtherProto(EtherProtocol::Stp));
        builder.and(Primitive::EtherProto(EtherProtocol::Ipx));
        builder.and(Primitive::EtherProto(EtherProtocol::Netbeui));
        builder.and(Primitive::EtherProto(EtherProtocol::Lat));
        builder.and(Primitive::EtherProto(EtherProtocol::Moprc));
        builder.and(Primitive::EtherProto(EtherProtocol::Mopdl));
        builder.and(Primitive::EtherProto(EtherProtocol::Loopback)); // should not be shortened
        builder.or(Primitive::IsoProto(IsoProtocol::Clnp));
        builder.and(Primitive::IsoProto(IsoProtocol::Esis));
        builder.and(Primitive::IsoProto(IsoProtocol::Isis));

        let expr = builder.build();

        let expected = concat!(
            "tcp and udp and icmp and proto igmp ",
            "or ip and ip6 and arp and rarp and atalk and aarp and decnet and iso and stp and ipx and netbeui and ",
            "lat and moprc and mopdl and ether proto loopback ",
            "or clnp and esis and isis"
        );

        assert_eq!(expr.to_string(), expected);
    }

    #[test]
    fn test_verbose() {
        let mut options = FilterOptions::new();
        options.use_verbosity(PrimitiveVerbosity::Verbose);

        let mut builder = FilterBuilder::with(Primitive::Proto(NetProtocol::Tcp), &options);
        builder.and(Primitive::Udp);
        builder.and(Primitive::Icmp);
        builder.or(Primitive::Ip);
        builder.and(Primitive::Ip6);
        builder.and(Primitive::Arp);
        builder.and(Primitive::Rarp);
        builder.and(Primitive::Atalk);
        builder.and(Primitive::Aarp);
        builder.and(Primitive::Decnet);
        builder.and(Primitive::Iso);
        builder.and(Primitive::Stp);
        builder.and(Primitive::Ipx);
        builder.and(Primitive::Netbeui);
        builder.and(Primitive::Lat);
        builder.and(Primitive::Moprc);
        builder.and(Primitive::Mopdl);
        builder.or(Primitive::Clnp);
        builder.and(Primitive::Esis);
        builder.and(Primitive::Isis);

        let expr = builder.build();

        let expected = concat!(
            "proto \\tcp and proto \\udp and proto \\icmp ",
            "or ether proto \\ip and ether proto \\ip6 and ether proto \\arp and ether proto \\rarp ",
            "and ether proto \\atalk and ether proto \\aarp and ether proto \\decnet ",
            "and ether proto \\iso and ether proto \\stp and ether proto \\ipx ",
            "and ether proto \\netbeui and ether proto \\lat and ether proto \\moprc ",
            "and ether proto \\mopdl ",
            "or iso proto \\clnp and iso proto \\esis and iso proto \\isis"
        );

        assert_eq!(expr.to_string(), expected);
    }

    #[test]
    fn test_exact() {
        let mut options = FilterOptions::new();
        options.use_verbosity(PrimitiveVerbosity::Exact);

        let mut builder = FilterBuilder::with(Primitive::Tcp, &options);
        builder.and(Primitive::Proto(NetProtocol::Tcp));

        let expr = builder.build();

        assert_eq!(expr.to_string(), "tcp and proto \\tcp");
    }

    ///////////////////////////////////////////////////////////////////////////

    #[test]
    fn test_packet_access() {
        let mut inner_builder = ExpressionBuilder::new(Operand::Integer(5));
        inner_builder.right_shift(Operand::Integer(10));

        let inner_expression = inner_builder.build();

        let primitive = Primitive::Comparison(
            ExpressionBuilder::new(Operand::PacketData(QualifierProtocol::Icmp, inner_expression, 0)).build(),
            RelOp::Ne,
            ExpressionBuilder::new(Operand::Integer(10)).build(),
        );

        let options = FilterOptions::new();
        let expr = FilterBuilder::with(primitive, &options).build();

        assert_eq!(expr.to_string(), "icmp[(5 >> 10):0] != 10");
    }

    #[test]
    fn test_not() {
        let options = FilterOptions::new();
        let mut builder = FilterBuilder::with_not(Primitive::Tcp, &options);
        builder.or(Primitive::Udp);
        builder.or_not(Primitive::Icmp);
        builder.and_not(Primitive::Ip);

        let expr = builder.build();

        assert_eq!(expr.to_string(), "not tcp or udp or not icmp and not ip")
    }

    #[test]
    fn test_sub_filter() {
        let options = FilterOptions::new();
        let mut sub = FilterBuilder::with(Primitive::Udp, &options);
        sub.or(Primitive::Tcp);

        let mut builder = FilterBuilder::with(Primitive::Ip6, &options);
        builder.and_filter(sub);

        let expr = builder.build();

        assert_eq!(expr.to_string(), "ip6 and (udp or tcp)");
    }

    #[test]
    fn test_sub_filter_one_internal() {
        let options = FilterOptions::new();
        let sub = FilterBuilder::with(Primitive::Udp, &options);

        let mut builder = FilterBuilder::with(Primitive::Ip6, &options);
        builder.and_filter(sub);

        let expr = builder.build();

        assert_eq!(expr.to_string(), "ip6 and udp");
    }

    #[test]
    fn test_after_port() {
        let options = FilterOptions::new();
        let mut sub = FilterBuilder::with(Primitive::Tcp, &options);
        sub.and(Primitive::Port(10, None));

        let expr = FilterBuilder::with_filter(sub).build();

        assert_eq!(expr.to_string(), "(tcp and port 10)");
    }
}
