use crate::bpf::primitive::{Primitive, Qualifier};
use crate::bpf::token::{Token, TokenStream};

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
    /// todo!("Provide example of whitespace vs no whitespace in an express (5 * 10) ^ 2")
    /// ```
    pub whitespace: bool,

    /// Use symbols for primitive expressions rather than their word
    /// counterparts, defaults to `false`.
    /// # Example
    /// ```
    /// todo!("Provide example of words vs symbol operatos")
    /// ```
    pub symbol_operators: bool,

    /// Specifies whether to use a [`Qualifier`]'s more verbose or abbreviated
    /// variant if available, or follow the users exact specification. Defaults
    /// to [`QualifierVariant::Exact`].
    ///
    /// # Example
    /// ```
    /// todo!("Provide example of longer vs shorter variants")
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

struct FilterBuilder {
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
            }
            QualifierVariant::Short => match primitive.abbreviated() {
                Some(p) => p,
                None => primitive,
            }
        }
    }

    pub fn build(self) -> FilterExpression {
        let mut filter = String::new();

        for token in self.tokens {
            filter.push_str(token.repr(&self.options).as_str());
        }

        FilterExpression(filter)
    }
}

pub struct FilterExpression(String);