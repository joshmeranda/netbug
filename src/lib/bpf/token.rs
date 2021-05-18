use std::iter::FromIterator;
use std::vec::IntoIter;

use crate::bpf::expression::{BinOp, Operand};
use crate::bpf::primitive::{Identifier, Primitive, Qualifier, RelOp};

/// The second bool is just a dummy type to not break with the na,ed lifetime
pub struct TokenStream(Vec<Token>);

impl TokenStream {
    pub fn with(primitive: Primitive) -> TokenStream { primitive.into() }

    pub fn with_not(primitive: Primitive) -> TokenStream {
        let mut stream = Self::with(primitive);

        // prepend the token stream with a Not operator
        stream.0.insert(0, Token::Not);

        stream
    }
}

impl FromIterator<Token> for TokenStream {
    fn from_iter<T: IntoIterator<Item = Token>>(iter: T) -> Self { TokenStream(iter.into_iter().collect()) }
}

impl IntoIterator for TokenStream {
    type Item = Token;
    type IntoIter = TokenStreamIntoIter;

    fn into_iter(self) -> Self::IntoIter { TokenStreamIntoIter::new(self.0) }
}

impl<'a> IntoIterator for &'a TokenStream {
    type Item = &'a Token;
    type IntoIter = TokenStreamIterator<'a>;

    fn into_iter(self) -> Self::IntoIter { TokenStreamIterator::new(&self.0) }
}

///////////////////////////////////////////////////////////////////////////////

pub struct TokenStreamIntoIter {
    tokens: Vec<Token>,
}

impl TokenStreamIntoIter {
    fn new(tokens: Vec<Token>) -> TokenStreamIntoIter { Self { tokens } }
}

impl Iterator for TokenStreamIntoIter {
    type Item = Token;

    fn next(&mut self) -> Option<Self::Item> { self.tokens.pop() }
}

///////////////////////////////////////////////////////////////////////////////

pub struct TokenStreamIterator<'a> {
    tokens: &'a Vec<Token>,
    index:  usize,
}

impl<'a> TokenStreamIterator<'a> {
    fn new(tokens: &'a Vec<Token>) -> TokenStreamIterator { Self { tokens, index: 0 } }
}

impl<'a> Iterator for TokenStreamIterator<'a> {
    type Item = &'a Token;

    fn next(&mut self) -> Option<Self::Item> {
        let token = self.tokens.get(self.index);

        if token.is_some() {
            self.index += 1;
        }

        token
    }
}

///////////////////////////////////////////////////////////////////////////////

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
