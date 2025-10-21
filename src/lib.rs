//! Cellwall - A Rust reimplementation of bubblewrap
//!
//! Cellwall is a sandboxing tool that uses Linux namespaces to create
//! isolated environments for running applications.

// Public modules - exposed for the binary

// Internal modules - only visible within the crate
pub(crate) mod bind_mount;
pub(crate) mod capabilities;
pub(crate) mod cli;
pub(crate) mod mount;
pub(crate) mod namespace;
pub(crate) mod network;
pub(crate) mod sandbox;
pub(crate) mod setup;
pub(crate) mod utils;

pub use cli::Args;
pub use sandbox::SandboxConfig;
