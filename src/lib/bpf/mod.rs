pub mod expression;
mod filter;
pub mod primitive;
mod token;

use std::collections::VecDeque;
use std::error::Error;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::net::IpAddr;
use std::ops::Range;

use crate::bpf::expression::{BinOp, Operand};
use crate::bpf::primitive::{Action, Host, Identifier, Primitive, Qualifier, ReasonCode, RelOp};

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
