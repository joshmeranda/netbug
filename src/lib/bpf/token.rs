use std::iter::FromIterator;
use std::vec::IntoIter;

use crate::bpf::expression::{BinOp, Operand};
use crate::bpf::primitive::{Identifier, Primitive, Qualifier, RelOp};
use crate::bpf::filter::FormatOptions;

/// The second bool is just a dummy type to not break with the na,ed lifetime
pub struct TokenStream(Vec<Token>);

// todo: probably ok to allow for direct manipulation sicne this will not be a
// user facing struct (provide a push method)
impl TokenStream {
    pub fn new() -> TokenStream { Self(vec![]) }

    pub fn push(&mut self, token: Token) { self.0.push(token); }

    pub fn push_primitive(&mut self, primitive: Primitive) {
        Into::<TokenStream>::into(primitive)
            .into_iter()
            .for_each(|token| self.push(token));
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

impl Token {
    pub fn repr(&self, options: &FormatOptions) -> String {
        match self {
            Token::OpenParentheses => "(".to_owned(),
            Token::CloseParentheses => ")".to_owned(),
            Token::And => match options.symbol_operators {
                true => "&&".to_owned(),
                false => "and".to_owned(),
            }
            Token::Or => match options.symbol_operators {
                true => "||".to_owned(),
                false => "or".to_owned(),
            }
            Token::Not => match options.symbol_operators {
                true => "!".to_owned(),
                false => "not".to_owned(),
            }
            Token::Escape => "\\".to_owned(),
            Token::Id(id) => id.to_string(),
            Token::Operand(op) => op.to_string(),
            Token::Operator(op) => op.as_ref().to_owned(),
            Token::RelationalOperator(op) => op.as_ref().to_owned(),
            Token::Qualifier(qualifier) => qualifier.as_ref().to_owned(),
        }
    }
}