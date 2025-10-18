//! Command-line interface

use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "cellwall")]
#[command(version)]
#[command(about = "Run applications in a sandbox using Linux namespaces")]
#[command(
    long_about = "Cellwall is a Rust reimplementation of bubblewrap, a setuid implementation \
                        of a subset of user namespaces. It allows unprivileged users to run \
                        applications in isolated environments."
)]
pub struct Args {
    /// Create a new user namespace
    #[arg(long)]
    pub unshare_user: bool,

    /// Try to create a new user namespace (don't fail if unsupported)
    #[arg(long)]
    pub unshare_user_try: bool,

    /// Create a new IPC namespace
    #[arg(long)]
    pub unshare_ipc: bool,

    /// Create a new PID namespace
    #[arg(long)]
    pub unshare_pid: bool,

    /// Create a new network namespace
    #[arg(long)]
    pub unshare_net: bool,

    /// Create a new UTS namespace (hostname)
    #[arg(long)]
    pub unshare_uts: bool,

    /// Create a new cgroup namespace
    #[arg(long)]
    pub unshare_cgroup: bool,

    /// Try to create a new cgroup namespace (don't fail if unsupported)
    #[arg(long)]
    pub unshare_cgroup_try: bool,

    /// Unshare all namespaces
    #[arg(long)]
    pub unshare_all: bool,

    /// Retain the network namespace (only with --unshare-all)
    #[arg(long)]
    pub share_net: bool,

    /// Custom UID in the sandbox
    #[arg(long)]
    pub uid: Option<u32>,

    /// Custom GID in the sandbox
    #[arg(long)]
    pub gid: Option<u32>,

    /// Custom hostname in the sandbox
    #[arg(long)]
    pub hostname: Option<String>,

    /// Change to this directory
    #[arg(long)]
    pub chdir: Option<PathBuf>,

    /// Clear all environment variables
    #[arg(long)]
    pub clearenv: bool,

    /// Set an environment variable (can be used multiple times)
    #[arg(long, value_names = ["VAR", "VALUE"], num_args = 2)]
    pub setenv: Vec<String>,

    /// Unset an environment variable (can be used multiple times)
    #[arg(long, value_name = "VAR")]
    pub unsetenv: Vec<String>,

    /// Bind mount SOURCE to DEST
    #[arg(long, value_names = ["SOURCE", "DEST"], num_args = 2)]
    pub bind: Vec<String>,

    /// Bind mount SOURCE to DEST (read-only)
    #[arg(long, value_names = ["SOURCE", "DEST"], num_args = 2)]
    pub ro_bind: Vec<String>,

    /// Bind mount SOURCE to DEST (ignore if source doesn't exist)
    #[arg(long, value_names = ["SOURCE", "DEST"], num_args = 2)]
    pub bind_try: Vec<String>,

    /// Read-only bind mount SOURCE to DEST (ignore if source doesn't exist)
    #[arg(long, value_names = ["SOURCE", "DEST"], num_args = 2)]
    pub ro_bind_try: Vec<String>,

    /// Bind mount SOURCE to DEST with device access
    #[arg(long, value_names = ["SOURCE", "DEST"], num_args = 2)]
    pub dev_bind: Vec<String>,

    /// Bind mount SOURCE to DEST with device access (ignore if source doesn't exist)
    #[arg(long, value_names = ["SOURCE", "DEST"], num_args = 2)]
    pub dev_bind_try: Vec<String>,

    /// Change permissions of PATH (must already exist)
    #[arg(long, value_names = ["OCTAL", "PATH"], num_args = 2)]
    pub chmod: Vec<String>,

    /// Mount new proc filesystem at PATH
    #[arg(long, value_name = "PATH")]
    pub proc: Vec<PathBuf>,

    /// Mount new dev filesystem at PATH
    #[arg(long, value_name = "PATH")]
    pub dev: Vec<PathBuf>,

    /// Mount new tmpfs at PATH
    #[arg(long, value_name = "PATH")]
    pub tmpfs: Vec<PathBuf>,

    /// Create a directory at PATH
    #[arg(long, value_name = "PATH")]
    pub dir: Vec<PathBuf>,

    /// Create a symlink from SOURCE to DEST
    #[arg(long, value_names = ["SOURCE", "DEST"], num_args = 2)]
    pub symlink: Vec<String>,

    /// Remount PATH as read-only
    #[arg(long, value_name = "PATH")]
    pub remount_ro: Vec<PathBuf>,

    /// Create a new session
    #[arg(long)]
    pub new_session: bool,

    /// Kill process when parent dies
    #[arg(long)]
    pub die_with_parent: bool,

    /// Run as PID 1 (don't create reaper process)
    #[arg(long)]
    pub as_pid_1: bool,

    /// Disable further use of user namespaces inside sandbox
    #[arg(long)]
    pub disable_userns: bool,

    /// Add a capability when running as privileged user
    #[arg(long, value_name = "CAP")]
    pub cap_add: Vec<String>,

    /// Drop a capability when running as privileged user
    #[arg(long, value_name = "CAP")]
    pub cap_drop: Vec<String>,

    /// Load seccomp rules from file descriptor
    #[arg(long, value_name = "FD")]
    pub seccomp: Option<i32>,

    /// Set logging level (error, warn, info, debug, trace)
    #[arg(long, value_name = "LEVEL", default_value = "warn")]
    pub log_level: String,

    /// The command and arguments to run
    #[arg(trailing_var_arg = true, required = true)]
    pub command: Vec<String>,
}

impl Args {
    /// Validate the arguments
    pub fn validate(&self) -> eyre::Result<()> {
        if self.command.is_empty() {
            eyre::bail!("No command specified");
        }

        if self.share_net && !self.unshare_all {
            eyre::bail!("--share-net can only be used with --unshare-all");
        }

        if self.hostname.is_some() && !self.unshare_uts {
            eyre::bail!("--hostname requires --unshare-uts");
        }

        if self.as_pid_1 && !self.unshare_pid {
            eyre::bail!("--as-pid-1 requires --unshare-pid");
        }

        if self.disable_userns && !self.unshare_user {
            eyre::bail!("--disable-userns requires --unshare-user");
        }

        // With clap's num_args = 2, these should always be even, but validate anyway
        if !self.bind.len().is_multiple_of(2) {
            eyre::bail!("--bind requires pairs of source and destination");
        }

        if !self.ro_bind.len().is_multiple_of(2) {
            eyre::bail!("--ro-bind requires pairs of source and destination");
        }

        if !self.symlink.len().is_multiple_of(2) {
            eyre::bail!("--symlink requires pairs of source and destination");
        }

        // Validate log level
        let valid_levels = ["error", "warn", "info", "debug", "trace"];
        if !valid_levels.contains(&self.log_level.to_lowercase().as_str()) {
            eyre::bail!(
                "Invalid log level '{}'. Valid levels are: error, warn, info, debug, trace",
                self.log_level
            );
        }

        Ok(())
    }
}
