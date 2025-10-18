//! Cellwall - A Rust reimplementation of bubblewrap
//!
//! Cellwall is a sandboxing tool that uses Linux namespaces to create
//! isolated environments for running applications.

pub mod bind_mount;
pub mod capabilities;
pub mod cli;
pub mod mount;
pub mod namespace;
pub mod network;
pub mod sandbox;
pub mod setup;
pub mod status;
pub mod utils;

pub use eyre::Result;
