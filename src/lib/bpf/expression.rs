use std::collections::VecDeque;
use std::iter::FromIterator;
use std::slice::Iter;
use std::vec::IntoIter;

use crate::bpf::primitive::{QualifierProtocol, Qualifier};
use crate::bpf::token::{Token, TokenStream};
use crate::bpf::{BpfError, Result};
use crate::bpf::filter::FilterBuilder;

/// A simple wrapper around a [String] allowing for cleaner typing.
#[derive(Clone, Debug, PartialEq)]
pub struct Expression {
    tokens: TokenStream,
}

impl Expression {
    /// No syntax checking is performed, any valid string can be passed here.
    /// For any real syntax checking, please use [ExpressionBuilder] to
    /// construct the [Expression].
    pub fn new(tokens: Vec<Token>) -> Expression {
        Expression {
            tokens: TokenStream::from_iter(tokens.into_iter()),
        }
    }

    /// Build the token stream for this [`Express`].
    pub fn stream(self) -> TokenStream { self.tokens }
}

/// An operand, either an unsigned integer or packet data, in an expression.
#[derive(Clone, Debug, PartialEq)]
pub enum Operand {
    Integer(usize),

    PacketData(QualifierProtocol, Expression, usize),
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
/// # use netbug::bpf::expression::{ExpressionBuilder, BinOp, Expression, Operand};
/// # use netbug::bpf::token::Token;
///
/// let expr = ExpressionBuilder::new(Operand::Integer(5))
///     .plus(Operand::Integer(1))
///     .build();
///
/// let expected = Expression::new(vec![
///         Token::Integer(5),
///         Token::Operator(BinOp::Plus),
///         Token::Integer(1),
///     ]);
///
/// assert_eq!(expr, expected)
/// ```
///
/// or expressions containing a special data packet accessor (ie
/// proto[offset:size])
///
/// ```
/// # use netbug::bpf::expression::{ExpressionBuilder, BinOp, Expression, Operand};
/// # use netbug::bpf::primitive::{QualifierProtocol, Qualifier};
/// # use netbug::bpf::token::Token;
///
/// let expr = ExpressionBuilder::new(Operand::PacketData(QualifierProtocol::Ether, Expression::new(vec![Token::Integer(0)]), 1))
///     .and(Operand::Integer(1))
///     .build();
///
/// let expected = Expression::new(vec![
///         Token::Qualifier(Qualifier::Proto(QualifierProtocol::Ether)),
///         Token::OpenBracket,
///         Token::Integer(0),
///         Token::Colon,
///         Token::Integer(1),
///         Token::CloseBracket,
///         Token::Operator(BinOp::And),
///         Token::Integer(1)
///     ]);
///
/// assert_eq!(expr, expected)
/// ```
/// For goruping values in parentheses (sub expressions) there are 2 options:
///
/// 1 ) Construct the builder with [`ExpressionBuilder::from_expr`], used when the expression
/// starts of the larger expresison
///
/// 2 ) Adding the expressions via [`ExpressionBuilder::expr`]
///
/// If the given expression has only 1 operand then no parenthesis as re aded as they would be redundant, but will be added in all other circumstances.
///
/// ```
/// # use netbug::bpf::expression::{ExpressionBuilder, Expression, Operand, BinOp};
/// # use netbug::bpf::token::Token;
///
/// let expr = ExpressionBuilder::from_expr(ExpressionBuilder::new(Operand::Integer(5))
///         .times(Operand::Integer(10))
///         .build())
///     .raise(Operand::Integer(2))
///     .build();
///
/// let expected = Expression::new(vec![
///         Token::OpenParentheses,
///         Token::Integer(5),
///         Token::Operator(BinOp::Multiply),
///         Token::Integer(10),
///         Token::CloseParentheses,
///         Token::Operator(BinOp::Exponent),
///         Token::Integer(2)
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
        let mut builder = ExpressionBuilder {
            tokens: vec![],
        };

        builder.add_operand(operand);

        builder

    }

    /// Construct a new [`ExpressionBuilder`] using `expr` as the first value(s)
    /// in the expression, with optional parentheses.
    pub fn from_expr(expr: Expression) -> ExpressionBuilder {
        let mut builder = ExpressionBuilder { tokens: vec![] };

        builder.add_expr(expr);

        builder
    }

    fn add_operand(&mut self, operand: Operand) {
        match operand {
            Operand::Integer(n) => self.tokens.push(Token::Integer(n)),
            Operand::PacketData(proto, offset, len) => {
                self.tokens.push(Token::Qualifier(Qualifier::Proto(proto)));
                self.tokens.push(Token::OpenBracket);
                self.add_expr(offset);
                self.tokens.push(Token::Colon);
                self.tokens.push(Token::Integer(len));
                self.tokens.push(Token::CloseBracket);
            }
        }
    }

    fn add_expr(&mut self, expr: Expression) {
        let parenthesis = expr.tokens.len() > 1;

        if parenthesis {
            self.tokens.push(Token::OpenParentheses);
        }

        expr.stream().into_iter().for_each(|token| self.tokens.push(token.clone()));

        if parenthesis {
            self.tokens.push(Token::CloseParentheses);
        }
    }

    pub fn plus(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Plus));
        self.add_operand(operand);
        self
    }

    pub fn minus(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Minus));
        self.add_operand(operand);
        self
    }

    pub fn times(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Multiply));
        self.add_operand(operand);
        self
    }

    pub fn divide(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Divide));
        self.add_operand(operand);
        self
    }

    pub fn modulus(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Modulus));
        self.add_operand(operand);
        self
    }

    pub fn and(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::And));
        self.add_operand(operand);
        self
    }

    pub fn or(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Or));
        self.add_operand(operand);
        self
    }

    pub fn raise(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::Exponent));
        self.add_operand(operand);
        self
    }

    pub fn left_shift(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::LeftShift));
        self.add_operand(operand);
        self
    }

    pub fn right_shift(mut self, operand: Operand) -> ExpressionBuilder {
        self.tokens.push(Token::Operator(BinOp::RightShift));
        self.add_operand(operand);
        self
    }

    /// Add the tokens from one expression to the current one, with optional
    /// parentheses.
    pub fn expr(mut self, expr: Expression) -> ExpressionBuilder {
        self.add_expr(expr);

        self
    }

    /// Build the expression and return a [String] representation of the
    /// constructed expression.
    pub fn build(&self) -> Expression {
        let tokens = self.tokens.iter().map(|token| token.clone()).collect();

        Expression::new(tokens)
    }
}
