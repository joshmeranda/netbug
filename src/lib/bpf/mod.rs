//! This module aims to provide the ability to programmatically build Berkley
//! Packet Filter (BPF) expressions, with as little opportunity for failure as
//! possible.
//!
//! NOTE: This module is likely to be move into its own crate in the future
pub mod expression;
pub mod filter;
pub mod primitive;
pub mod token;
