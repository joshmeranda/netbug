use std::collections::VecDeque;
use crate::bpf::BpfError;
use crate::bpf::Result;
use crate::bpf::primitive::Protocol;

/// A simple wrapper around a [String] allowing for cleaner typing.
#[derive(Debug, PartialEq)]
pub struct Expression(String);

impl Expression {
    /// No syntax checking is performed, any valid string can be passed here. For any real syntax checking, please use [ExpressionBuilder] to construct the [Expression].
    pub fn new(inner: String) -> Expression {
        Expression(inner)
    }
}

/// An operand, either an unsigned integer or packet data, in an expression.
pub enum Operand {
    Integer(usize),

    PacketData(Protocol, Expression, usize)
}

impl ToString for Operand {
    fn to_string(&self) -> String {
        match self {
            Operand::Integer(n) => n.to_string(),
            // todo: should handle the size being omitted if 1q (eg `ether[1]` points only to the first byte)
            Operand::PacketData(proto, offset, size) => {
                format!("{}[{}:{}]", proto.as_ref(), offset.0, size.to_string())
            }
        }
    }
}

/// Any of the typical binary operators.
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

/// Allows for building an arithmetic expression as a string. Currently parenthesis are not supported.
///
/// # Examples
///
/// The builder can be used to construct simple numerical expressions
/// ```
/// use netbug::bpf::expression::{ExpressionBuilder, BinOp, Expression};
///
/// let expr = ExpressionBuilder::new()
///     .number(5)
///     .operator(BinOp::Plus)
///     .number(1)
///     .build()
///     .unwrap();
///
/// let expected = Expression::new(String::from("5+1"));
///
/// assert_eq!(expected, expr);
/// ```
///
/// or expressions containing a special data packet accessor (ie proto[offset:size])
/// ```
/// use netbug::bpf::expression::{ExpressionBuilder, BinOp, Expression};
/// use netbug::bpf::primitive::Protocol;
///
/// let expr = ExpressionBuilder::new()
///     .packet_data(Protocol::Ether, Expression::new(String::from("0")), 1 )
///     .and()
///     .number(1)
///     .build()
///     .unwrap();
///
/// let expected = Expression::new(String::from("ether[0:1]&1"));
///
/// assert_eq!(expected, expr);
/// ```
///
/// todo: add formatting options (eg whitespace)
/// todo: shold support parentheses
pub struct ExpressionBuilder {
    operands: VecDeque<Operand>,

    operators: VecDeque<BinOp>
}

impl ExpressionBuilder {
    pub fn new() -> ExpressionBuilder{
        ExpressionBuilder {
            operands: VecDeque::new(),
            operators: VecDeque::new(),
        }
    }

    pub fn operand(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push_back(operand);
        self
    }

    pub fn number(mut self, n: usize) -> ExpressionBuilder {
        self.operand(Operand::Integer(n))
    }

    pub fn packet_data(mut self, proto: Protocol, offset: Expression, size: usize) -> ExpressionBuilder {
        self.operand(Operand::PacketData(proto, offset, size))
    }

    pub fn operator(mut self, operator: BinOp) -> ExpressionBuilder {
        self.operators.push_back(operator);
        self
    }

    pub fn plus(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Plus)
    }

    pub fn minus(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Minus)
    }

    pub fn multiply(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Multiply)
    }

    pub fn divide(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Divide)
    }

    pub fn modulus(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Modulus)
    }

    pub fn and(mut self) -> ExpressionBuilder {
        self.operator(BinOp::And)
    }

    pub fn or(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Or)
    }

    pub fn exponent(mut self) -> ExpressionBuilder {
        self.operator(BinOp::Exponent)
    }

    pub fn left_shift(mut self) -> ExpressionBuilder {
        self.operator(BinOp::LeftShift)
    }

    pub fn right_shift(mut self) -> ExpressionBuilder {
        self.operator(BinOp::RightShift)
    }

    /// Build the expression and return a [String] representation of the constructed expression.
    ///
    /// # Errors
    /// If the builder would construct an invalid expression (bad syntax, etc).
    ///
    /// ```
    /// use netbug::bpf::expression::{ExpressionBuilder, BinOp};
    ///
    /// let missing_tail_operand = ExpressionBuilder::new()
    ///     .number(5)
    ///     .operator(BinOp::Plus)
    ///     .build();
    ///
    /// assert!(missing_tail_operand.is_err());
    ///
    /// let unexpected_operand = ExpressionBuilder::new()
    ///     .number(5)
    ///     .number(10)
    ///     .build();
    ///
    /// assert!(unexpected_operand.is_err());
    ///
    /// let unexpected_operator = ExpressionBuilder::new()
    ///     .plus()
    ///     .number(5)
    ///     .build();
    ///
    /// assert!(unexpected_operator.is_err());
    /// ```
    pub fn build(&self) -> Result<Expression> {
        if self.operands.is_empty() {
            return Err(BpfError::ExpressionSyntax(String::from("Expected operand found none")));
        }

        let mut operands = self.operands.iter();
        let mut operators = self.operators.iter();

        let mut expression = String::new();
        expression.push_str(operands.next().unwrap().to_string().as_str());

        let mut operand = operands.next();
        let mut operator = operators.next();

        // while ! operands. && ! self.operators.is_empty() {
        while operand.is_some() && operator.is_some() {
            expression.push_str(operator.unwrap().as_ref());
            expression.push_str(operand.unwrap().to_string().as_str());

            operand = operands.next();
            operator = operators.next();
        }

        if operand.is_none() && operator.is_none() {
            Ok(Expression::new(expression))
        } else if operand.is_some() {
            Err(BpfError::ExpressionSyntax(String::from(format!("Expected end of expression or operator, found '{}'", operand.unwrap().to_string()))))
        } else if operator.is_some() {
            Err(BpfError::ExpressionSyntax(String::from(format!("Expected operand, found '{}'", operator.unwrap().as_ref()))))
        } else {
            unreachable!()
        }
    }
}