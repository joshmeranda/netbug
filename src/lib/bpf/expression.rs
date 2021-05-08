use std::collections::VecDeque;
use std::vec::IntoIter;

use crate::bpf::primitive::QualifyProtocol;
use crate::bpf::{BpfError, Result};

/// A simple wrapper around a [String] allowing for cleaner typing.
#[derive(Debug, PartialEq)]
pub struct Expression {
    tokens: Vec<ExprToken>,
}

impl Expression {
    /// No syntax checking is performed, any valid string can be passed here.
    /// For any real syntax checking, please use [ExpressionBuilder] to
    /// construct the [Expression].
    pub fn new(tokens: Vec<ExprToken>) -> Expression { Expression { tokens } }
}

/// An operand, either an unsigned integer or packet data, in an expression.
#[derive(Debug, PartialEq)]
pub enum Operand {
    Integer(usize),

    /// Represents an [Expression] wrapped in parenthesis.
    Expr(Expression),

    PacketData(QualifyProtocol, Expression, usize),
}

impl ToString for Operand {
    fn to_string(&self) -> String { todo!() }
}

/// Any of the typical binary operators.
#[derive(Debug, PartialEq)]
pub enum BinOp {
    Plus,
    Minus,
    Multiply,
    Divide,
    Modulus,
    And,
    Or,
    Exponent,
    LeftShift,
    RightShift,
}

impl AsRef<str> for BinOp {
    fn as_ref(&self) -> &str {
        match self {
            BinOp::Plus => "+",
            BinOp::Minus => "-",
            BinOp::Multiply => "*",
            BinOp::Divide => "/",
            BinOp::Modulus => "%",
            BinOp::And => "&",
            BinOp::Or => "|",
            BinOp::Exponent => "^",
            BinOp::LeftShift => "<<",
            BinOp::RightShift => ">>",
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum ExprToken {
    Operand(Operand),
    Operator(BinOp),
}

impl ToString for ExprToken {
    fn to_string(&self) -> String {
        match self {
            ExprToken::Operand(op) => op.to_string(),
            ExprToken::Operator(op) => op.as_ref().to_owned(),
        }
    }
}

/// Allows for building an arithmetic expression as a string.
///
/// # Examples
///
/// The builder can be used to construct simple numerical expressions
/// ```
/// use netbug::bpf::expression::{ExpressionBuilder, BinOp, Expression, Operand, ExprToken};
///
/// let expr = ExpressionBuilder::new(Operand::Integer(5))
///     .plus(Operand::Integer(1))
///     .build();
///
/// let expected = Expression::new(vec![
///         ExprToken::Operand(Operand::Integer(5)),
///         ExprToken::Operator(BinOp::Plus),
///         ExprToken::Operand(Operand::Integer(1)),
///     ]);
///
/// assert_eq!(expected, expr);
/// ```
///
/// or expressions containing a special data packet accessor (ie
/// proto[offset:size])
///
/// ```
/// use netbug::bpf::expression::{ExpressionBuilder, BinOp, Expression, Operand, ExprToken};
/// use netbug::bpf::primitive::QualifyProtocol;
///
/// let expr = ExpressionBuilder::new(Operand::PacketData(QualifyProtocol::Ether, Expression::new(vec![ExprToken::Operand(Operand::Integer(0))]), 1))
///     .and(Operand::Integer(1))
///     .build();
///
/// let expected = Expression::new(vec![
///         ExprToken::Operand(Operand::PacketData(QualifyProtocol::Ether, Expression::new(vec![ExprToken::Operand(Operand::Integer(0))]), 1)),
///         ExprToken::Operator(BinOp::And),
///         ExprToken::Operand(Operand::Integer(1))
///     ]);
///
/// assert_eq!(expected, expr);
/// ```
///
/// For grouping multiple operrands via parenthesis, use the [`Operand::Expr`]
/// variant. Ideally the inner [`Expression`] should be build with this builder
/// struct to ensure the end expression is valid..
///
/// ```
/// use netbug::bpf::expression::{ExpressionBuilder, Expression, Operand, ExprToken, BinOp};
///
/// let expr = ExpressionBuilder::new(Operand::Expr(ExpressionBuilder::new(Operand::Integer(5))
///         .times(Operand::Integer(10))
///         .build()))
///     .raise(Operand::Integer(2))
///     .build();
///
/// let expected = Expression::new(vec![
///         ExprToken::Operand(Operand::Expr(Expression::new(vec![
///             ExprToken::Operand(Operand::Integer(5)),
///             ExprToken::Operator(BinOp::Multiply),
///             ExprToken::Operand(Operand::Integer(10))
///         ]))),
///         ExprToken::Operator(BinOp::Exponent),
///         ExprToken::Operand(Operand::Integer(2))
///     ]);
///
/// assert_eq!(expected, expr)
/// ```
pub struct ExpressionBuilder {
    tokens: Vec<ExprToken>,
}

impl ExpressionBuilder {
    /// Construct a new expression builder with `operand` as the initial value.
    pub fn new(operand: Operand) -> ExpressionBuilder {
        ExpressionBuilder {
            tokens: vec![ExprToken::Operand(operand)],
        }
    }

    pub fn plus(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(ExprToken::Operator(BinOp::Plus));
        self.tokens.push(ExprToken::Operand(operand));
        self
    }

    pub fn minus(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(ExprToken::Operator(BinOp::Minus));
        self.tokens.push(ExprToken::Operand(operand));
        self
    }

    pub fn times(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(ExprToken::Operator(BinOp::Multiply));
        self.tokens.push(ExprToken::Operand(operand));
        self
    }

    pub fn divide(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(ExprToken::Operator(BinOp::Divide));
        self.tokens.push(ExprToken::Operand(operand));
        self
    }

    pub fn modulus(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(ExprToken::Operator(BinOp::Modulus));
        self.tokens.push(ExprToken::Operand(operand));
        self
    }

    pub fn and(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(ExprToken::Operator(BinOp::And));
        self.tokens.push(ExprToken::Operand(operand));
        self
    }

    pub fn or(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(ExprToken::Operator(BinOp::Or));
        self.tokens.push(ExprToken::Operand(operand));
        self
    }

    pub fn raise(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(ExprToken::Operator(BinOp::Exponent));
        self.tokens.push(ExprToken::Operand(operand));
        self
    }

    pub fn left_shift(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(ExprToken::Operator(BinOp::LeftShift));
        self.tokens.push(ExprToken::Operand(operand));
        self
    }

    pub fn right_shift(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(ExprToken::Operator(BinOp::RightShift));
        self.tokens.push(ExprToken::Operand(operand));
        self
    }

    /// Build the expression and return a [String] representation of the
    /// constructed expression.
    pub fn build(self) -> Expression { Expression::new(self.tokens) }
}
