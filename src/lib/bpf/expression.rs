use std::collections::VecDeque;
use crate::bpf::BpfError;
use crate::bpf::Result;
use crate::bpf::primitive::Protocol;

/// An operand, either an unsigned integer or packet data, in an expression.
pub enum Operand {
    Integer(usize),

    PacketData(Protocol, usize, usize)
}

impl ToString for Operand {
    fn to_string(&self) -> String {
        match self {
            Operand::Integer(n) => n.to_string(),
            // todo: should handle the size being omitted if 1q (eg `ether[1]` points only to the first byte)
            Operand::PacketData(proto, offset, size) =>
                format!("{}[{}:{}]", proto.as_ref(), offset.to_string(), size.to_string()),
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
/// use netbug::bpf::expression::{ExpressionBuilder, BinOp};
///
/// let expr = ExpressionBuilder::new()
///     .number(5)
///     .operator(BinOp::Plus)
///     .number(1)
///     .build()
///     .unwrap();
///
/// let expected = String::from("5+1");
///
/// assert_eq!(expected, expr);
/// ```
///
/// or expressions containing a special data packet accessor (ie proto[offset:size])
/// ```
/// use netbug::bpf::expression::{ExpressionBuilder, BinOp};
/// use netbug::bpf::primitive::Protocol;
///
/// let expr = ExpressionBuilder::new()
///     .packet_data(Protocol::Ether, 0, 1 )
///     .and()
///     .number(1)
///     .build()
///     .unwrap();
///
/// let expected = String::from("ether[0:1]&1");
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
        println!("===  operand: {}", operand.to_string());

        self.operands.push_back(operand);
        self
    }

    pub fn number(mut self, n: usize) -> ExpressionBuilder {
        self.operand(Operand::Integer(n))
    }

    pub fn packet_data(mut self, proto: Protocol, offset: usize, size: usize) -> ExpressionBuilder {
        self.operand(Operand::PacketData(proto, offset, size))
    }

    pub fn operator(mut self, operator: BinOp) -> ExpressionBuilder {
        println!("=== operator: {}", operator.as_ref());

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
    /// let unexpected_operand = ExpressionBuilder::new()
    ///     .number(5)
    ///     .number(10)
    ///     .build();
    ///
    /// let unexpected_operator = ExpressionBuilder::new()
    ///     .plus()
    ///     .number(5)
    ///     .build();
    ///
    /// assert!(missing_tail_operand.is_err());
    /// assert!(unexpected_operand.is_err());
    /// assert!(unexpected_operator.is_err());
    /// ```
    pub fn build(mut self) -> Result<String> {
        let mut expression = String::new();

        if self.operands.is_empty() {
            return Err(BpfError::ExpressionSyntax(String::from("Expected operand found none")));
        }

        expression.push_str(self.operands.pop_front().unwrap().to_string().as_str());

        while ! self.operands.is_empty() && ! self.operators.is_empty() {
            expression.push_str(self.operators.pop_front().unwrap().as_ref());
            expression.push_str(self.operands.pop_front().unwrap().to_string().as_str());
        }

        if ! self.operands.is_empty() {
            return Err(BpfError::ExpressionSyntax(String::from(format!("Expected end of expression or operator, found '{}'", self.operands.pop_front().unwrap().to_string()))));
        }

        if ! self.operators.is_empty() {
            return Err(BpfError::ExpressionSyntax(String::from(format!("Expected operand, found '{}'", self.operators.pop_front().unwrap().as_ref()))));
        }

        Ok(expression)
    }
}