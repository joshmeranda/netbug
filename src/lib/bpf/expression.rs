use std::collections::VecDeque;
use crate::bpf::BpfError;
use crate::bpf::Result;
use crate::bpf::primitive::QualifyProtocol;

/// A simple wrapper around a [String] allowing for cleaner typing.
#[derive(Debug, PartialEq)]
pub struct Expression(pub String);

impl Expression {
    /// No syntax checking is performed, any valid string can be passed here. For any real syntax checking, please use [ExpressionBuilder] to construct the [Expression].
    pub fn new(inner: String) -> Expression {
        Expression(inner)
    }
}

/// An operand, either an unsigned integer or packet data, in an expression.
pub enum Operand {
    Integer(usize),

    /// Represents an [Expression] wrapped in parenthesis.
    Expr(Expression),

    PacketData(QualifyProtocol, Expression, usize)
}

impl ToString for Operand {
    fn to_string(&self) -> String {
        match self {
            Operand::Integer(n) => n.to_string(),
            Operand::Expr(expr) => format!("({})", expr.0),

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

/// Allows for building an arithmetic expression as a string.
///
/// # Examples
///
/// The builder can be used to construct simple numerical expressions
/// ```
/// use netbug::bpf::expression::{ExpressionBuilder, BinOp, Expression, Operand};
///
/// let expr = ExpressionBuilder::new(Operand::Integer(5))
///     .plus(Operand::Integer(1))
///     .build();
///
/// let expected = Expression::new(String::from("5+1"));
///
/// assert_eq!(expected, expr);
/// ```
///
/// or expressions containing a special data packet accessor (ie proto[offset:size])
///
/// ```
/// use netbug::bpf::expression::{ExpressionBuilder, BinOp, Expression, Operand};
/// use netbug::bpf::primitive::QualifyProtocol;
///
/// let expr = ExpressionBuilder::new(Operand::PacketData(QualifyProtocol::Ether, Expression::new(String::from("0")), 1 ))
///     .and(Operand::Integer(1))
///     .build();
///
/// let expected = Expression::new(String::from("ether[0:1]&1"));
///
/// assert_eq!(expected, expr);
/// ```
///
/// For grouping multiple operrands via parenthesis, use the [`Operand::Expr`] variant. Ideally the inner [`Expression`] should be build with this builder struct to ensure the end expression is valid..
///
/// ```
/// use netbug::bpf::expression::{ExpressionBuilder, Expression, Operand};
///
/// let expr = ExpressionBuilder::new(Operand::Expr(ExpressionBuilder::new(Operand::Integer(5))
///         .times(Operand::Integer(10))
///         .build()))
///     .raise(Operand::Integer(2))
///     .build();
///
/// let expected = Expression::new(String::from("(5*10)^2"));
///
/// assert_eq!(expected, expr)
/// ```
///
/// todo: add formatting options (eg whitespace)
pub struct ExpressionBuilder {
    operands: Vec<Operand>,

    operators: Vec<BinOp>
}

impl ExpressionBuilder {
    /// Construct a new expression builder with `operand` as the initial value.
    pub fn new(operand: Operand) -> ExpressionBuilder{
        ExpressionBuilder {
            operands: vec![operand],
            operators: vec![],
        }
    }

    fn operand(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push(operand);
        self
    }

    fn operator(mut self, operator: BinOp) -> ExpressionBuilder {
        self.operators.push(operator);
        self
    }

    pub fn plus(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push(operand);
        self.operators.push(BinOp::Plus);
        self
    }

    pub fn minus(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push(operand);
        self.operators.push(BinOp::Minus);
        self
    }

    pub fn times(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push(operand);
        self.operators.push(BinOp::Multiply);
        self
    }

    pub fn divide(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push(operand);
        self.operators.push(BinOp::Divide);
        self
    }

    pub fn modulus(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push(operand);
        self.operators.push(BinOp::Modulus);
        self
    }

    pub fn and(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push(operand);
        self.operators.push(BinOp::And);
        self
    }

    pub fn or(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push(operand);
        self.operators.push(BinOp::Or);
        self
    }

    pub fn raise(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push(operand);
        self.operators.push(BinOp::Exponent);
        self
    }

    pub fn left_shift(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push(operand);
        self.operators.push(BinOp::LeftShift);
        self
    }

    pub fn right_shift(mut self, operand: Operand) -> ExpressionBuilder {
        self.operands.push(operand);
        self.operators.push(BinOp::RightShift);
        self
    }

    /// Build the expression and return a [String] representation of the constructed expression.
    pub fn build(&self) -> Expression {
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

        Expression::new(expression)
    }
}