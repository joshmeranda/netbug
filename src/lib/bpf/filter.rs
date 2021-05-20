use crate::bpf::primitive::{Primitive, Qualifier};
use crate::bpf::token::{Token, TokenStream, TokenStreamIntoIter, TokenStreamIterator};

pub enum QualifierVariant {
    Exact,
    Long,
    Short,
}

/// Allows for specifying how the resulting BPF program is to be formatted as a
/// string. todo: consider protocol number?
pub struct FormatOptions {
    /// Use whitespace to separate operands from operators when serializing
    /// arithmetic expression. Defaults to `true`.
    ///
    /// # Example
    /// ```
    /// # use netbug::bpf::filter::{FormatOptions, FilterBuilder, FilterExpression};
    /// # use netbug::bpf::primitive::{Primitive, RelOp};
    /// # use netbug::bpf::expression::{ExpressionBuilder, Operand};
    ///
    /// let mut options = FormatOptions::default();
    /// options.whitespace = true;
    ///
    /// let inner_expression = ExpressionBuilder::new(Operand::Integer(5))
    ///     .plus(Operand::Integer(10))
    ///     .build();
    ///
    /// let builder = FilterBuilder::with(Primitive::Comparison(
    ///                                     ExpressionBuilder::from_expr(inner_expression).raise(Operand::Integer(2)).build(),
    ///                                     RelOp::Eq,
    ///                                     ExpressionBuilder::new(Operand::Integer(5)).build()));
    ///
    /// let actual = builder.build();
    /// let expected = FilterExpression(String::from("(5 + 10) ^ 2 = 5"));
    ///
    /// assert_eq!(actual, expected);
    /// ```
    pub whitespace: bool,

    /// Use symbols for primitive expressions rather than their word
    /// counterparts, defaults to `false`.
    /// # Example
    /// ```
    /// use netbug::bpf::filter::{FormatOptions, FilterBuilder, FilterExpression};
    /// use netbug::bpf::primitive::Primitive;
    ///
    /// let builder = FilterBuilder::with(Primitive::Udp)
    ///     .or(Primitive::Tcp);
    ///
    /// assert_eq!(builder.build(), FilterExpression("udp or tcp".to_owned()));
    ///
    /// let mut options = FormatOptions::default();
    /// options.symbol_operators = true;
    ///
    /// let builder = FilterBuilder::with(Primitive::Udp)
    ///     .or(Primitive::Tcp)
    ///     .options(options);
    ///
    /// assert_eq!(builder.build(), FilterExpression("udp || tcp".to_owned()));
    ///
    /// ```
    pub symbol_operators: bool,

    /// Specifies whether to use a [`Qualifier`]'s more verbose or abbreviated
    /// variant if available, or follow the users exact specification. Defaults
    /// to [`QualifierVariant::Exact`].
    ///
    /// # Example
    /// ```
    /// // todo!("Provide example of longer vs shorter variants")
    /// ```
    pub variant: QualifierVariant,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            whitespace:       true,
            symbol_operators: false,
            variant:          QualifierVariant::Exact,
        }
    }
}

pub struct FilterBuilder {
    options: FormatOptions,
    tokens:  TokenStream,
}

impl FilterBuilder {
    fn new() -> FilterBuilder {
        FilterBuilder {
            options: FormatOptions::default(),
            tokens:  TokenStream::new(),
        }
    }

    pub fn with(primitive: Primitive) -> FilterBuilder {
        let mut builder = Self::new();

        builder.tokens.push_primitive(builder.format_primitive(primitive));

        builder
    }

    pub fn with_not(primitive: Primitive) -> FilterBuilder {
        let mut builder = Self::new();

        builder.tokens.push(Token::Not);
        builder.tokens.push_primitive(builder.format_primitive(primitive));

        builder
    }

    pub fn options(mut self, options: FormatOptions) -> FilterBuilder {
        self.options = options;

        self
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
        match self.options.variant {
            QualifierVariant::Exact => primitive,
            QualifierVariant::Long => match primitive.verbose() {
                Some(p) => p,
                None => primitive,
            },
            QualifierVariant::Short => match primitive.abbreviated() {
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
                Token::CloseParentheses => false,
                _ => true,
            },
            Token::OpenParentheses | Token::OpenBracket | Token::Colon | Token::Escape => false,
            Token::And | Token::Or | Token::Not | Token::Id(_) => true,
            Token::Integer(_) => match next.unwrap() {
                Token::CloseParentheses | Token::CloseBracket => false,
                _ => true,
            }
            Token::RelationalOperator(_) => self.options.whitespace,
            Token::Qualifier(qualifier) => match qualifier {
                Qualifier::Proto(_) => match next.unwrap() {
                    // the special case of a packet data access expression
                    Token::OpenBracket => false,
                    _ => false
                },
                _ => true
            }
        }
    }

    pub fn build(self) -> FilterExpression {
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
pub struct FilterExpression(pub String);

#[cfg(test)]
mod test {
    use crate::bpf::filter::{FilterBuilder, FilterExpression};
    use crate::bpf::primitive::Primitive;

    #[test]
    fn test_basic_ok() {
        let builder = FilterBuilder::with(Primitive::Tcp).or(Primitive::Udp);

        let actual = builder.build();
        let expected = FilterExpression(String::from("tcp or udp"));

        assert_eq!(expected, actual);
    }
}
