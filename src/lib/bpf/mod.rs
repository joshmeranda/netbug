pub mod expression;
pub mod primitive;

use std::net::IpAddr;
use std::ops::Range;
use std::collections::VecDeque;
use crate::bpf::expression::{BinOp, Operand};
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::fmt;

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

struct FilterBuilder { }

impl FilterBuilder {
}

