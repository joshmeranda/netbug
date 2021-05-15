use crate::bpf::primitive::{Primitive, Qualifier};
use crate::bpf::Token;

/// Simple trait allowing types to be converted into an iterator of tokens with the given [`FormatOptions.`]
pub trait TokenStream {
    fn stream(&self) -> core::slice::Iter<Token>;
}

pub enum QualifierVariant {
    Exact,
    Long,
    Short
}

/// Allows for specifying how the resulting BPF program is to be formatted as a string.
/// todo: consider protocol number?
pub struct FormatOptions {
    /// Use whitespace to separate operands from operators when serializing
    /// arithmetic expression.
    ///
    /// # Example
    /// ```
    /// todo!("Provide example of whitespace vs no whitespace in an express (5 * 10) ^ 2")
    /// ```
    whitespace: bool,

    /// Use symbols for primitive expressions rather than their word
    /// counterparts, defaults to `false`.
    /// # Example
    /// ```
    /// todo!("Provide example of words vs symbol operatos")
    /// ```
    symbol_operators: bool,

    /// Specifies whether to use a [`Qualifier`]'s more verbose or abbreviated variant if available, or follow the users exact specification.
    ///
    /// # Example
    /// ```
    /// todo!("Provide example of longer vs shorter variants")
    /// ```
    variant: QualifierVariant
}

struct FilterBuilder {
    options: FormatOptions,
    tokens:  Vec<Token>,
}

impl FilterBuilder {
    pub fn with(primitive: Primitive) -> FilterBuilder {}

    pub fn with_not(primitive: Primitive) -> FilterBuilder {}

    fn add_primitive(&mut self, primitive: Primitive) {}

    pub fn and(mut self, primitive: Primitive) -> FilterBuilder { self }

    pub fn and_not(mut self, primitive: Primitive) -> FilterBuilder { self }

    pub fn or(mut self, primitive: Primitive) -> FilterBuilder { self }

    pub fn or_not(mut self, primitive: Primitive) -> FilterBuilder { self }
}
