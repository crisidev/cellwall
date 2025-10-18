//! Cellwall - A Rust reimplementation of bubblewrap

use cellwall::cli::Args;
use cellwall::sandbox::{SandboxConfig, run_sandbox};
use clap::Parser;
use eyre::Result;
use nix::unistd::{getgid, getuid};

fn main() -> Result<()> {
    // Install color_eyre for beautiful error messages
    color_eyre::install()?;

    // Parse command-line arguments early to get log level
    let args = Args::parse();

    // Validate arguments
    args.validate()?;

    // Initialize logging - use --log-level if set, otherwise respect RUST_LOG
    // If RUST_LOG is set, it takes precedence over --log-level
    if std::env::var("RUST_LOG").is_err() {
        env_logger::Builder::from_env(
            env_logger::Env::default().default_filter_or(&args.log_level),
        )
        .init();
    } else {
        // RUST_LOG is set, use it and ignore --log-level
        env_logger::Builder::from_env(env_logger::Env::default()).init();
    }

    log::info!("Starting cellwrap sandbox");
    log::debug!("Real UID: {}, Real GID: {}", getuid(), getgid());

    // Create sandbox configuration
    let config = SandboxConfig::from_args(&args)?;

    // Run the sandbox
    run_sandbox(config)?;

    Ok(())
}
