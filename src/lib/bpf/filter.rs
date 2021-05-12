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

    fn add_primitive(&mut self, primitive: Primitive) { }

    pub fn and(mut self, primitive: Primitive) -> FilterBuilder { self }

    pub fn and_not(mut self, primitive: Primitive) -> FilterBuilder { self }

    pub fn or(mut self, primitive: Primitive) -> FilterBuilder { self }

    pub fn or_not(mut self, primitive: Primitive) -> FilterBuilder { self }
}
