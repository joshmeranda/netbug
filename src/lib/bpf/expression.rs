use std::collections::VecDeque;
use std::vec::IntoIter;

use crate::bpf::primitive::QualifierProtocol;
use crate::bpf::{BpfError, Result, Token};
use crate::bpf::filter::TokenStream;
use std::slice::Iter;

/// A simple wrapper around a [String] allowing for cleaner typing.
#[derive(Clone, Debug, PartialEq)]
pub struct Expression {
    tokens: Vec<Token>,
}

impl Expression {
    /// No syntax checking is performed, any valid string can be passed here.
    /// For any real syntax checking, please use [ExpressionBuilder] to
    /// construct the [Expression].
    pub fn new(tokens: Vec<Token>) -> Expression { Expression { tokens } }
}

impl TokenStream for Expression {
    fn stream(&self) -> Iter<Token> { self.tokens.iter() }
}

/// An operand, either an unsigned integer or packet data, in an expression.
#[derive(Clone, Debug, PartialEq)]
pub enum Operand {
    Integer(usize),

    PacketData(QualifierProtocol, Expression, usize),
}

impl ToString for Operand {
    fn to_string(&self) -> String { todo!() }
}

/// Any of the typical binary operators.
#[derive(Clone, Debug, PartialEq)]
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

/// Allows for building an arithmetic expression as a string.
///
/// # Examples
///
/// The builder can be used to construct simple numerical expressions
/// ```
/// use netbug::bpf::expression::{ExpressionBuilder, BinOp, Expression, Operand, Token};
/// use netbug::bpf::Token;
///
/// let expr = ExpressionBuilder::new(Operand::Integer(5))
///     .plus(Operand::Integer(1))
///     .build();
///
/// let expected = Expression::new(vec![
///         Token::Operand(Operand::Integer(5)),
///         Token::Operator(BinOp::Plus),
///         Token::Operand(Operand::Integer(1)),
///     ]);
///
/// assert_eq!(expr, expected)
/// ```
///
/// or expressions containing a special data packet accessor (ie
/// proto[offset:size])
///
/// ```
/// use netbug::bpf::expression::{ExpressionBuilder, BinOp, Expression, Operand, Token};
/// use netbug::bpf::primitive::QualifierProtocol;
/// use netbug::bpf::Token;
///
/// let expr = ExpressionBuilder::new(Operand::PacketData(QualifierProtocol::Ether, Expression::new(vec![Token::Operand(Operand::Integer(0))]), 1))
///     .and(Operand::Integer(1))
///     .build();
///
/// let expected = Expression::new(vec![
///         Token::Operand(Operand::PacketData(QualifierProtocol::Ether, Expression::new(vec![Token::Operand(Operand::Integer(0))]), 1)),
///         Token::Operator(BinOp::And),
///         Token::Operand(Operand::Integer(1))
///     ]);
///
/// assert_eq!(expr, expected)
/// ```
/// For goruping values in parentheses (sub expressions) there are 2 options:
///
/// 1 ) Construct the builder with [`from_expr`], used when the expression
/// starts of the larger expresison 2 ) Adding the expressions vie [`expr`]
///
/// Both of the methods above take a `parentheses` arguments which specifies
/// whether the axpression being added should be wrapped in parethesises. If the
/// given expression is composed of only a single operand, parentheses will not
/// be added regardless of the value of `parentheses`.
///
/// ```
/// use netbug::bpf::expression::{ExpressionBuilder, Expression, Operand, Token, BinOp};
/// use netbug::bpf::Token;
///
/// let expr = ExpressionBuilder::from_expr(ExpressionBuilder::new(Operand::Integer(5))
///         .times(Operand::Integer(10))
///         .build(), true)
///     .raise(Operand::Integer(2))
///     .build();
///
/// let expected = Expression::new(vec![
///         Token::OpenParentheses,
///         Token::Operand(Operand::Integer(5)),
///         Token::Operator(BinOp::Multiply),
///         Token::Operand(Operand::Integer(10)),
///         Token::CloseParentheses,
///         Token::Operator(BinOp::Exponent),
///         Token::Operand(Operand::Integer(2))
///     ]);
///
/// assert_eq!(expr, expected)
/// ```
pub struct ExpressionBuilder {
    tokens: Vec<Token>,
}

impl ExpressionBuilder {
    /// Construct a new expression builder with `operand` as the initial value.
    pub fn new(operand: Operand) -> ExpressionBuilder {
        ExpressionBuilder {
            tokens: vec![Token::Operand(operand)],
        }
    }

    /// Construct a new [`ExpressionBuilder`] using `expr` as the first value(s)
    /// in the expression, with optional parentheses.
    pub fn from_expr(expr: Expression, parentheses: bool) -> ExpressionBuilder {
        let builder = ExpressionBuilder { tokens: vec![] };

        builder.expr(expr, parentheses)
    }

    pub fn plus(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Plus));
        self.tokens.push(Token::Operand(operand));
        self
    }

    pub fn minus(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Minus));
        self.tokens.push(Token::Operand(operand));
        self
    }

    pub fn times(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Multiply));
        self.tokens.push(Token::Operand(operand));
        self
    }

    pub fn divide(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Divide));
        self.tokens.push(Token::Operand(operand));
        self
    }

    pub fn modulus(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Modulus));
        self.tokens.push(Token::Operand(operand));
        self
    }

    pub fn and(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::And));
        self.tokens.push(Token::Operand(operand));
        self
    }

    pub fn or(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Or));
        self.tokens.push(Token::Operand(operand));
        self
    }

    pub fn raise(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Exponent));
        self.tokens.push(Token::Operand(operand));
        self
    }

    pub fn left_shift(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::LeftShift));
        self.tokens.push(Token::Operand(operand));
        self
    }

    pub fn right_shift(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::RightShift));
        self.tokens.push(Token::Operand(operand));
        self
    }

    /// Add the tokens from one expression to the current one, with optional
    /// parentheses.
    pub fn expr(mut self, expr: Expression, parentheses: bool) -> ExpressionBuilder {
        if parentheses && expr.tokens.len() > 1 {
            self.tokens.push(Token::OpenParentheses);
        }

        expr.tokens.iter().for_each(|token| self.tokens.push(token.clone()));

        if parentheses && expr.tokens.len() > 1 {
            self.tokens.push(Token::CloseParentheses);
        }

        self
    }

    /// Build the expression and return a [String] representation of the
    /// constructed expression.
    pub fn build(self) -> Expression { Expression::new(self.tokens) }
}
