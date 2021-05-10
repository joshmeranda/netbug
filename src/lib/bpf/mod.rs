pub mod expression;
mod filter;
pub mod primitive;

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::ops::Range;

use crate::bpf::expression::{BinOp, Operand};
use crate::bpf::primitive::{Primitive, Qualifier, Host};

pub type Result<T> = std::result::Result<T, BpfError>;

#[derive(Debug)]
pub enum BpfError {
    ExpressionSyntax(String),
}

impl Display for BpfError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            BpfError::ExpressionSyntax(reason) => write!(f, "Invalid syntax: {}", reason),
        }
    }
}

impl Error for BpfError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            BpfError::ExpressionSyntax(_) => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Token {
    OpenParentheses,
    CloseParentheses,
    And,
    Or,
    Not,
    Host(IpAddr),
    Port(u16),
    Operand(Operand),
    Operator(BinOp),
    Qualifier(Qualifier),
    Primitive(Primitive),
}
