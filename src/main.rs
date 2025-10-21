//! Cellwall - A Rust reimplementation of bubblewrap

use clap::Parser;
use eyre::Result;
use nix::unistd::{getgid, getuid};

use cellwall::cli::Args;
use cellwall::sandbox::SandboxConfig;

fn main() -> Result<()> {
    color_eyre::install()?;
    let args = Args::parse();
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

    // Run the sandbox
    let sandbox = SandboxConfig::from_args(&args)?;
    sandbox.run()
}
