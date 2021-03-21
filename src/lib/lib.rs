#![feature(thread_spawn_unchecked)]

pub mod behavior;
pub mod client;
pub mod config;
pub mod error;
pub mod message;
pub mod protocols;
pub mod server;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate num_derive;

/// The total length og the PcapMessage header as raw bytes. The header is
/// composed of the packet version number (u8), pcap name length (u8), and the
/// total data length (u64).
pub const HEADER_LENGTH: usize = 10;

/// This buffer size must be large enough to contain at least the header
/// [HEADER_LENGTH] and interface file name which on most systems should be 16
/// byte including the null byte.
const BUFFER_SIZE: usize = 1024;

/// The current message protocol version, will allow future iterations of the
/// netbug server to be backwards compatible with stale clients.
const MESSAGE_VERSION: u8 = 0;
