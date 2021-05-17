use std::vec::IntoIter;
use crate::bpf::primitive::{Qualifier, RelOp, Identifier};
use crate::bpf::expression::{BinOp, Operand};
use std::iter::FromIterator;

pub struct TokenStream(Vec<Token>);

impl FromIterator<Token> for TokenStream {
    fn from_iter<T: IntoIterator<Item=Token>>(iter: T) -> Self {
        TokenStream(iter.into_iter().collect())
    }
}

impl IntoIterator for TokenStream {
    type Item = Token;
    type IntoIter = std::vec::IntoIter<Self::Item>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

/// A basic token to represent the most atomic components of a BPF program.
#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    OpenParentheses,
    CloseParentheses,
    And,
    Or,
    Not,
    Escape,
    Id(Identifier),
    Operand(Operand),
    Operator(BinOp),
    RelationalOperator(RelOp),
    Qualifier(Qualifier),
}