//! Cellwall - A Rust reimplementation of bubblewrap

use clap::Parser;
use cellwall::cli::Args;
use cellwall::sandbox::{run_sandbox, SandboxConfig};
use eyre::Result;
use nix::unistd::{getgid, getuid};

fn main() -> Result<()> {
    // Install color_eyre for beautiful error messages
    color_eyre::install()?;

    // Initialize logging - respect RUST_LOG, default to warn
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .init();

    // Parse command-line arguments
    let args = Args::parse();

    // Validate arguments
    args.validate()?;

    log::info!("Starting cellwrap sandbox");
    log::debug!("Real UID: {}, Real GID: {}", getuid(), getgid());

    // Create sandbox configuration
    let config = SandboxConfig::from_args(&args)?;

    // Run the sandbox
    run_sandbox(config)?;

    Ok(())
}
