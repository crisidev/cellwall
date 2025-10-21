//! Main sandbox execution logic

use crate::capabilities::{apply_capability_changes, drop_all_caps, set_ambient_capabilities};
use crate::cli::Args;
use crate::mount::make_slave;
use crate::namespace::{unshare_namespaces, write_uid_gid_map};
use crate::network::setup_loopback;
use crate::setup::{SetupOp, execute_setup_op};
use eyre::{Context, Result};
use nix::sched::CloneFlags;
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Gid, Uid, chdir, fork, getgid, getuid, setsid};
use std::path::PathBuf;

/// Main sandbox configuration
pub struct SandboxConfig {
    pub command: Vec<String>,
    pub setup_ops: Vec<SetupOp>,
    pub unshare_user: bool,
    pub unshare_pid: bool,
    pub unshare_net: bool,
    pub unshare_ipc: bool,
    pub unshare_uts: bool,
    pub unshare_cgroup: bool,
    pub sandbox_uid: Option<Uid>,
    pub sandbox_gid: Option<Gid>,
    pub hostname: Option<String>,
    pub chdir: Option<PathBuf>,
    pub new_session: bool,
    pub die_with_parent: bool,
    pub clearenv: bool,
    pub setenv: Vec<(String, String)>,
    pub unsetenv: Vec<String>,
    pub cap_add: Vec<String>,
    pub cap_drop: Vec<String>,
    pub seccomp_fd: Option<i32>,
}

impl SandboxConfig {
    /// Create sandbox config from CLI arguments
    pub fn from_args(args: &Args) -> Result<Self> {
        let mut setup_ops = Vec::new();

        // Parse bind mounts
        for chunk in args.bind.chunks(2) {
            if let [source, dest] = chunk {
                setup_ops.push(SetupOp::BindMount {
                    source: PathBuf::from(source),
                    dest: PathBuf::from(dest),
                    readonly: false,
                    devices: false,
                    recursive: true,
                });
            }
        }

        // Parse read-only bind mounts
        for chunk in args.ro_bind.chunks(2) {
            if let [source, dest] = chunk {
                setup_ops.push(SetupOp::BindMount {
                    source: PathBuf::from(source),
                    dest: PathBuf::from(dest),
                    readonly: true,
                    devices: false,
                    recursive: true,
                });
            }
        }

        // Parse proc mounts
        for dest in &args.proc {
            setup_ops.push(SetupOp::MountProc { dest: dest.clone() });
        }

        // Parse dev mounts
        for dest in &args.dev {
            setup_ops.push(SetupOp::MountDev { dest: dest.clone() });
        }

        // Parse tmpfs mounts
        for dest in &args.tmpfs {
            setup_ops.push(SetupOp::MountTmpfs {
                dest: dest.clone(),
                mode: 0o755,
                size: None,
            });
        }

        // Parse directory creation
        for path in &args.dir {
            setup_ops.push(SetupOp::CreateDir {
                path: path.clone(),
                mode: 0o755,
            });
        }

        // Parse symlinks
        for chunk in args.symlink.chunks(2) {
            if let [source, dest] = chunk {
                setup_ops.push(SetupOp::CreateSymlink {
                    source: source.clone(),
                    dest: PathBuf::from(dest),
                });
            }
        }

        // Parse remount-ro
        for path in &args.remount_ro {
            setup_ops.push(SetupOp::RemountRo { path: path.clone() });
        }

        // Parse bind-try mounts
        for chunk in args.bind_try.chunks(2) {
            if let [source, dest] = chunk {
                setup_ops.push(SetupOp::BindMountTry {
                    source: PathBuf::from(source),
                    dest: PathBuf::from(dest),
                    readonly: false,
                    devices: false,
                    recursive: true,
                });
            }
        }

        // Parse ro-bind-try mounts
        for chunk in args.ro_bind_try.chunks(2) {
            if let [source, dest] = chunk {
                setup_ops.push(SetupOp::BindMountTry {
                    source: PathBuf::from(source),
                    dest: PathBuf::from(dest),
                    readonly: true,
                    devices: false,
                    recursive: true,
                });
            }
        }

        // Parse dev-bind mounts
        for chunk in args.dev_bind.chunks(2) {
            if let [source, dest] = chunk {
                setup_ops.push(SetupOp::BindMount {
                    source: PathBuf::from(source),
                    dest: PathBuf::from(dest),
                    readonly: false,
                    devices: true,
                    recursive: true,
                });
            }
        }

        // Parse dev-bind-try mounts
        for chunk in args.dev_bind_try.chunks(2) {
            if let [source, dest] = chunk {
                setup_ops.push(SetupOp::BindMountTry {
                    source: PathBuf::from(source),
                    dest: PathBuf::from(dest),
                    readonly: false,
                    devices: true,
                    recursive: true,
                });
            }
        }

        // Parse chmod operations
        for chunk in args.chmod.chunks(2) {
            if let [mode_str, path] = chunk {
                let mode = u32::from_str_radix(mode_str.trim_start_matches("0"), 8)
                    .wrap_err_with(|| format!("Invalid octal mode: {}", mode_str))?;
                setup_ops.push(SetupOp::Chmod {
                    path: PathBuf::from(path),
                    mode,
                });
            }
        }

        // Parse bind-fd mounts
        for chunk in args.bind_fd.chunks(2) {
            if let [fd_str, dest] = chunk {
                let fd = fd_str
                    .parse::<i32>()
                    .wrap_err_with(|| format!("Invalid file descriptor: {}", fd_str))?;
                if fd < 0 {
                    eyre::bail!("File descriptor must be non-negative: {}", fd);
                }
                setup_ops.push(SetupOp::BindMountFd {
                    fd,
                    dest: PathBuf::from(dest),
                    readonly: false,
                });
            }
        }

        // Parse ro-bind-fd mounts
        for chunk in args.ro_bind_fd.chunks(2) {
            if let [fd_str, dest] = chunk {
                let fd = fd_str
                    .parse::<i32>()
                    .wrap_err_with(|| format!("Invalid file descriptor: {}", fd_str))?;
                if fd < 0 {
                    eyre::bail!("File descriptor must be non-negative: {}", fd);
                }
                setup_ops.push(SetupOp::BindMountFd {
                    fd,
                    dest: PathBuf::from(dest),
                    readonly: true,
                });
            }
        }

        let mut unshare_user = args.unshare_user;
        let mut unshare_pid = args.unshare_pid;
        let mut unshare_net = args.unshare_net;
        let mut unshare_ipc = args.unshare_ipc;
        let mut unshare_uts = args.unshare_uts;
        let mut unshare_cgroup = args.unshare_cgroup;

        // Handle --unshare-all
        if args.unshare_all {
            unshare_user = true;
            unshare_pid = true;
            unshare_net = true;
            unshare_ipc = true;
            unshare_uts = true;
            unshare_cgroup = true;
        }

        // Handle --share-net (disable network namespace)
        if args.share_net {
            unshare_net = false;
        }

        // Parse setenv (comes in pairs: VAR VALUE VAR VALUE...)
        let mut setenv = Vec::new();
        for chunk in args.setenv.chunks(2) {
            if let [var, value] = chunk {
                setenv.push((var.clone(), value.clone()));
            }
        }

        Ok(Self {
            command: args.command.clone(),
            setup_ops,
            unshare_user,
            unshare_pid,
            unshare_net,
            unshare_ipc,
            unshare_uts,
            unshare_cgroup,
            sandbox_uid: args.uid.map(Uid::from_raw),
            sandbox_gid: args.gid.map(Gid::from_raw),
            hostname: args.hostname.clone(),
            chdir: args.chdir.clone(),
            new_session: args.new_session,
            die_with_parent: args.die_with_parent,
            clearenv: args.clearenv,
            setenv,
            unsetenv: args.unsetenv.clone(),
            cap_add: args.cap_add.clone(),
            cap_drop: args.cap_drop.clone(),
            seccomp_fd: args.seccomp,
        })
    }

    /// Run the sandbox
    pub fn run(self) -> Result<()> {
        log::info!("Starting sandbox setup");
        log::debug!("Command to execute: {:?}", self.command);

        let real_uid = getuid();
        let real_gid = getgid();
        log::debug!("Real UID: {}, Real GID: {}", real_uid, real_gid);

        let sandbox_uid = self.sandbox_uid.unwrap_or(real_uid);
        let sandbox_gid = self.sandbox_gid.unwrap_or(real_gid);
        log::debug!("Sandbox UID: {}, Sandbox GID: {}", sandbox_uid, sandbox_gid);

        // Build namespace flags
        let mut clone_flags = CloneFlags::empty();
        log::debug!("Building namespace configuration...");

        // Check if we're trying to mount proc (requires PID namespace)
        let needs_proc = self
            .setup_ops
            .iter()
            .any(|op| matches!(op, SetupOp::MountProc { .. }));
        log::debug!("Needs proc mount: {}", needs_proc);

        // Only create mount namespace if we have setup operations that need it
        let needs_mount_ns = !self.setup_ops.is_empty()
            || self.unshare_user
            || self.unshare_pid
            || self.unshare_net
            || self.unshare_ipc
            || self.unshare_uts
            || self.unshare_cgroup;
        log::debug!("Needs mount namespace: {}", needs_mount_ns);

        // If we need mount namespace but not running as root, we need user namespace
        let mut needs_user_ns = self.unshare_user;
        if needs_mount_ns && real_uid != Uid::from_raw(0) {
            needs_user_ns = true;
            log::debug!("Non-root user needs mount namespace, enabling user namespace");
        }

        // Mounting proc requires PID namespace
        let mut needs_pid_ns = self.unshare_pid;
        if needs_proc {
            needs_pid_ns = true;
            log::debug!("Proc mount requires PID namespace, enabling PID namespace");
        }

        if needs_mount_ns {
            clone_flags |= CloneFlags::CLONE_NEWNS;
            log::debug!("Enabling CLONE_NEWNS (mount namespace)");
        }

        if needs_user_ns {
            clone_flags |= CloneFlags::CLONE_NEWUSER;
            log::debug!("Enabling CLONE_NEWUSER (user namespace)");
        }
        if needs_pid_ns {
            clone_flags |= CloneFlags::CLONE_NEWPID;
            log::debug!("Enabling CLONE_NEWPID (PID namespace)");
        }
        if self.unshare_net {
            clone_flags |= CloneFlags::CLONE_NEWNET;
            log::debug!("Enabling CLONE_NEWNET (network namespace)");
        }
        if self.unshare_ipc {
            clone_flags |= CloneFlags::CLONE_NEWIPC;
            log::debug!("Enabling CLONE_NEWIPC (IPC namespace)");
        }
        if self.unshare_uts {
            clone_flags |= CloneFlags::CLONE_NEWUTS;
            log::debug!("Enabling CLONE_NEWUTS (UTS namespace)");
        }
        if self.unshare_cgroup {
            clone_flags |= CloneFlags::CLONE_NEWCGROUP;
            log::debug!("Enabling CLONE_NEWCGROUP (cgroup namespace)");
        }

        // Only unshare if we have namespaces to create
        if !clone_flags.is_empty() {
            log::info!("Unsharing namespaces: {:?}", clone_flags);
            unshare_namespaces(clone_flags)?;
            log::debug!("Successfully unshared namespaces");
        }

        // Fork if we need PID namespace or status reporting
        match unsafe { fork() }? {
            ForkResult::Parent { child } => {
                // Parent: report status, wait for child and exit with its status
                log::debug!("Parent process waiting for child PID {}", child);

                // Wait for child to exit
                match waitpid(child, None)? {
                    WaitStatus::Exited(_, status) => {
                        log::debug!("Child exited with status {}", status);

                        std::process::exit(status);
                    }
                    WaitStatus::Signaled(_, sig, _) => {
                        log::debug!("Child terminated by signal {}", sig);
                        let exit_code = 128 + sig as i32;

                        std::process::exit(exit_code);
                    }
                    _ => {
                        log::debug!("Child exited with unknown status");

                        std::process::exit(1);
                    }
                }
            }
            ForkResult::Child => {
                // Child continues with the sandbox setup
                log::debug!("Child process entered PID namespace, continuing setup...");
            }
        }

        // Setup user namespace mappings if needed
        if needs_user_ns {
            log::info!(
                "Setting up user namespace mappings: sandbox_uid={}, sandbox_gid={}, real_uid={}, real_gid={}",
                sandbox_uid,
                sandbox_gid,
                real_uid,
                real_gid
            );
            write_uid_gid_map(
                -1,
                sandbox_uid,
                real_uid,
                sandbox_gid,
                real_gid,
                None,
                true,
                false,
                Uid::from_raw(65534), // overflow_uid
                Gid::from_raw(65534), // overflow_gid
            )?;
            log::debug!("User namespace mappings written successfully");
        }

        // Setup network namespace
        if self.unshare_net {
            log::info!("Setting up network namespace (loopback interface)");
            setup_loopback().wrap_err("Failed to setup loopback interface")?;
            log::debug!("Loopback interface configured");
        }

        // Make root mount slave to prevent propagation (only if we have mount namespace)
        if needs_mount_ns {
            log::debug!("Making root mount slave to prevent propagation");
            make_slave("/")?;
            log::debug!("Root mount is now slave");
        }

        // Execute all setup operations
        log::info!("Executing {} setup operations", self.setup_ops.len());
        for (idx, op) in self.setup_ops.iter().enumerate() {
            log::debug!(
                "Setup operation {}/{}: {:?}",
                idx + 1,
                self.setup_ops.len(),
                op
            );
            execute_setup_op(op)?;
            log::debug!(
                "Setup operation {}/{} completed",
                idx + 1,
                self.setup_ops.len()
            );
        }
        log::info!("All setup operations completed successfully");

        // Set hostname if requested
        if let Some(hostname) = &self.hostname {
            log::info!("Setting hostname to: {}", hostname);
            nix::unistd::sethostname(hostname)?;
            log::debug!("Hostname set successfully");
        }

        // Setup die-with-parent (before changing directory/session)
        if self.die_with_parent {
            log::debug!("Setting PR_SET_PDEATHSIG to SIGKILL (die with parent)");
            set_pdeathsig(libc::SIGKILL)?;
            log::debug!("Parent death signal configured");
        }

        // Create new session if requested
        if self.new_session {
            log::debug!("Creating new session (setsid)");
            setsid()?;
            log::debug!("New session created");
        }

        // Change directory if requested
        if let Some(dir) = &self.chdir {
            log::info!("Changing directory to: {}", dir.display());
            chdir(dir.as_path())?;
            log::debug!("Directory changed successfully");
        }

        // Setup environment variables
        if self.clearenv {
            log::debug!("Clearing all environment variables");
            let var_count = std::env::vars().count();
            std::env::vars().for_each(|(key, _)| unsafe {
                std::env::remove_var(&key);
            });
            log::debug!("Cleared {} environment variables", var_count);
            // Keep PWD
            if let Ok(pwd) = std::env::current_dir() {
                unsafe {
                    std::env::set_var("PWD", pwd);
                }
                log::debug!("Restored PWD environment variable");
            }
        }

        for var in &self.unsetenv {
            log::debug!("Unsetting environment variable: {}", var);
            unsafe {
                std::env::remove_var(var);
            }
        }

        for (var, value) in &self.setenv {
            log::debug!("Setting environment variable: {}={}", var, value);
            unsafe {
                std::env::set_var(var, value);
            }
        }

        if !self.setenv.is_empty() {
            log::info!("Set {} environment variables", self.setenv.len());
        }

        // Log what we're about to execute BEFORE loading seccomp
        // (logging after seccomp can cause issues)
        log::info!("Preparing to execute command: {:?}", self.command);

        // Apply capability changes (only for root)
        if real_uid == Uid::from_raw(0) && (!self.cap_add.is_empty() || !self.cap_drop.is_empty()) {
            log::info!(
                "Applying capability changes: add={:?}, drop={:?}",
                self.cap_add,
                self.cap_drop
            );
            apply_capability_changes(&self.cap_add, &self.cap_drop)?;
            log::debug!("Capability changes applied successfully");
        }

        // Drop privileges before loading seccomp (if not root)
        if real_uid != Uid::from_raw(0) {
            log::debug!("Dropping all capabilities (non-root user)");
            drop_all_caps()?;
            log::debug!("All capabilities dropped");
        } else if needs_user_ns {
            // Set ambient capabilities for unprivileged execution
            log::debug!("Setting ambient capabilities for user namespace");
            set_ambient_capabilities()?;
            log::debug!("Ambient capabilities set");
        }

        // Apply seccomp filter if provided
        // IMPORTANT: This must be the LAST thing we do before exec!
        // After loading seccomp, we cannot safely do any Rust operations
        // (logging, error handling, etc.) as they may trigger syscalls or
        // memory operations that could conflict with the filter
        if let Some(fd) = self.seccomp_fd {
            log::info!("Loading seccomp filter from FD {}", fd);
            load_seccomp_from_fd(fd)?;
            // NO LOGGING AFTER THIS POINT - seccomp is active!
        } else {
            log::debug!("No seccomp filter requested");
        }

        // Execute the command immediately after seccomp
        log::info!("Executing command now: {:?}", self.command);
        exec_command(&self.command)?;

        Ok(())
    }
}

/// Set no new privileges flag (safer wrapper around prctl)
fn set_no_new_privs() -> Result<()> {
    unsafe {
        let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if ret != 0 {
            eyre::bail!(
                "Failed to set PR_SET_NO_NEW_PRIVS: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

/// Load seccomp BPF program (safer wrapper around prctl)
unsafe fn load_seccomp_bpf(prog: *const libc::c_void) -> Result<()> {
    unsafe {
        const PR_SET_SECCOMP: libc::c_int = 22;
        const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

        let ret = libc::prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER,
            prog as libc::c_ulong,
            0,
            0,
        );

        if ret != 0 {
            eyre::bail!(
                "Failed to load seccomp filter: {}",
                std::io::Error::last_os_error()
            );
        }

        Ok(())
    }
}

/// Read from file descriptor (safer wrapper around libc::read)
fn read_fd(fd: i32, buf: &mut [u8]) -> Result<usize> {
    unsafe {
        let n = libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len());
        if n < 0 {
            eyre::bail!(
                "Failed to read from FD: {}",
                std::io::Error::last_os_error()
            );
        }
        Ok(n as usize)
    }
}

/// Load seccomp filter from file descriptor
fn load_seccomp_from_fd(fd: i32) -> Result<()> {
    // Read the seccomp BPF program from the file descriptor
    // IMPORTANT: We must not take ownership of the FD (no from_raw_fd)
    // as that would close it when dropped, causing IO Safety violations
    let mut buffer = Vec::new();
    loop {
        let mut chunk = [0u8; 4096];
        let n = read_fd(fd, &mut chunk)?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..n]);
    }

    // Bubblewrap expects raw BPF instructions (array of sock_filter structs)
    // Each sock_filter is 8 bytes, so the total length must be a multiple of 8
    if buffer.len() % 8 != 0 {
        eyre::bail!("Invalid seccomp data, must be multiple of 8");
    }

    let filter_len = buffer.len() / 8;

    // First, set NO_NEW_PRIVS to allow seccomp without CAP_SYS_ADMIN
    set_no_new_privs()?;

    unsafe {
        // Prepare the sock_fprog structure
        // IMPORTANT: We use the buffer directly and don't drop it until after exec
        #[repr(C)]
        struct sock_fprog {
            len: libc::c_ushort,
            filter: *const libc::sock_filter,
        }

        let prog = sock_fprog {
            len: filter_len as libc::c_ushort,
            filter: buffer.as_ptr() as *const libc::sock_filter,
        };

        // Load the seccomp filter
        load_seccomp_bpf(&prog as *const _ as *const libc::c_void)?;

        // NOTE: We don't log here because we're already under seccomp!
        // Any Rust operations after loading seccomp can be dangerous

        // Keep buffer alive - the kernel makes a copy, so we don't need to leak it
        // but we want to make sure it lives until after the prctl call
        std::mem::forget(buffer);
    }

    Ok(())
}

/// Set parent death signal (safer wrapper around prctl)
fn set_pdeathsig(sig: libc::c_int) -> Result<()> {
    unsafe {
        let ret = libc::prctl(libc::PR_SET_PDEATHSIG, sig, 0, 0, 0);
        if ret != 0 {
            eyre::bail!(
                "Failed to set parent death signal: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

/// Execute a command
fn exec_command(command: &[String]) -> Result<()> {
    if command.is_empty() {
        eyre::bail!("No command specified");
    }

    // Use std::os::unix::process::CommandExt::exec which never returns
    // This is important when seccomp is loaded - we don't want ANY Rust
    // cleanup code to run after exec
    use std::os::unix::process::CommandExt;
    let mut cmd = std::process::Command::new(&command[0]);
    if command.len() > 1 {
        cmd.args(&command[1..]);
    }

    // exec() replaces the current process and never returns
    Err(cmd.exec().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Args;

    fn create_minimal_args() -> Args {
        Args {
            unshare_user: false,
            unshare_user_try: false,
            unshare_ipc: false,
            unshare_pid: false,
            unshare_net: false,
            unshare_uts: false,
            unshare_cgroup: false,
            unshare_cgroup_try: false,
            unshare_all: false,
            share_net: false,
            uid: None,
            gid: None,
            hostname: None,
            chdir: None,
            clearenv: false,
            setenv: vec![],
            unsetenv: vec![],
            bind: vec![],
            ro_bind: vec![],
            bind_try: vec![],
            ro_bind_try: vec![],
            dev_bind: vec![],
            dev_bind_try: vec![],
            bind_fd: vec![],
            ro_bind_fd: vec![],
            chmod: vec![],
            proc: vec![],
            dev: vec![],
            tmpfs: vec![],
            dir: vec![],
            symlink: vec![],
            remount_ro: vec![],
            new_session: false,
            die_with_parent: false,
            as_pid_1: false,
            disable_userns: false,
            cap_add: vec![],
            cap_drop: vec![],
            seccomp: None,
            log_level: "warn".to_string(),
            command: vec!["test".to_string()],
        }
    }

    #[test]
    fn test_from_args_minimal() -> Result<()> {
        let args = create_minimal_args();
        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.command, vec!["test"]);
        assert_eq!(config.setup_ops.len(), 0);
        assert!(!config.unshare_user);
        assert!(!config.unshare_pid);
        assert!(!config.clearenv);

        Ok(())
    }

    #[test]
    fn test_from_args_bind_mounts() -> Result<()> {
        let mut args = create_minimal_args();
        args.bind = vec!["/src1".to_string(), "/dst1".to_string()];
        args.ro_bind = vec!["/src2".to_string(), "/dst2".to_string()];

        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.setup_ops.len(), 2);

        // Check first bind mount
        match &config.setup_ops[0] {
            SetupOp::BindMount {
                source,
                dest,
                readonly,
                devices,
                recursive,
            } => {
                assert_eq!(source, &PathBuf::from("/src1"));
                assert_eq!(dest, &PathBuf::from("/dst1"));
                assert!(!readonly);
                assert!(!devices);
                assert!(recursive);
            }
            _ => panic!("Expected BindMount"),
        }

        // Check second bind mount (readonly)
        match &config.setup_ops[1] {
            SetupOp::BindMount {
                source,
                dest,
                readonly,
                devices,
                recursive,
            } => {
                assert_eq!(source, &PathBuf::from("/src2"));
                assert_eq!(dest, &PathBuf::from("/dst2"));
                assert!(readonly);
                assert!(!devices);
                assert!(recursive);
            }
            _ => panic!("Expected BindMount"),
        }

        Ok(())
    }

    #[test]
    fn test_from_args_dev_bind() -> Result<()> {
        let mut args = create_minimal_args();
        args.dev_bind = vec!["/dev/sda".to_string(), "/mnt/dev".to_string()];

        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.setup_ops.len(), 1);
        match &config.setup_ops[0] {
            SetupOp::BindMount {
                source,
                dest,
                readonly,
                devices,
                recursive,
            } => {
                assert_eq!(source, &PathBuf::from("/dev/sda"));
                assert_eq!(dest, &PathBuf::from("/mnt/dev"));
                assert!(!readonly);
                assert!(devices);
                assert!(recursive);
            }
            _ => panic!("Expected BindMount with devices=true"),
        }

        Ok(())
    }

    #[test]
    fn test_from_args_bind_try() -> Result<()> {
        let mut args = create_minimal_args();
        args.bind_try = vec!["/optional/src".to_string(), "/dst".to_string()];
        args.ro_bind_try = vec!["/optional/src2".to_string(), "/dst2".to_string()];

        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.setup_ops.len(), 2);
        assert!(matches!(config.setup_ops[0], SetupOp::BindMountTry { .. }));
        assert!(matches!(config.setup_ops[1], SetupOp::BindMountTry { .. }));

        Ok(())
    }

    #[test]
    fn test_from_args_filesystem_ops() -> Result<()> {
        let mut args = create_minimal_args();
        args.proc = vec![PathBuf::from("/proc")];
        args.dev = vec![PathBuf::from("/dev")];
        args.tmpfs = vec![PathBuf::from("/tmp")];
        args.dir = vec![PathBuf::from("/newdir")];
        args.remount_ro = vec![PathBuf::from("/readonly")];

        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.setup_ops.len(), 5);
        assert!(matches!(config.setup_ops[0], SetupOp::MountProc { .. }));
        assert!(matches!(config.setup_ops[1], SetupOp::MountDev { .. }));
        assert!(matches!(config.setup_ops[2], SetupOp::MountTmpfs { .. }));
        assert!(matches!(config.setup_ops[3], SetupOp::CreateDir { .. }));
        assert!(matches!(config.setup_ops[4], SetupOp::RemountRo { .. }));

        Ok(())
    }

    #[test]
    fn test_from_args_symlinks() -> Result<()> {
        let mut args = create_minimal_args();
        args.symlink = vec!["/target".to_string(), "/link".to_string()];

        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.setup_ops.len(), 1);
        match &config.setup_ops[0] {
            SetupOp::CreateSymlink { source, dest } => {
                assert_eq!(source, "/target");
                assert_eq!(dest, &PathBuf::from("/link"));
            }
            _ => panic!("Expected CreateSymlink"),
        }

        Ok(())
    }

    #[test]
    fn test_from_args_chmod() -> Result<()> {
        let mut args = create_minimal_args();
        args.chmod = vec!["755".to_string(), "/file".to_string()];

        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.setup_ops.len(), 1);
        match &config.setup_ops[0] {
            SetupOp::Chmod { path, mode } => {
                assert_eq!(path, &PathBuf::from("/file"));
                assert_eq!(*mode, 0o755);
            }
            _ => panic!("Expected Chmod"),
        }

        Ok(())
    }

    #[test]
    fn test_from_args_chmod_with_leading_zero() -> Result<()> {
        let mut args = create_minimal_args();
        args.chmod = vec!["0644".to_string(), "/file".to_string()];

        let config = SandboxConfig::from_args(&args)?;

        match &config.setup_ops[0] {
            SetupOp::Chmod { mode, .. } => {
                assert_eq!(*mode, 0o644);
            }
            _ => panic!("Expected Chmod"),
        }

        Ok(())
    }

    #[test]
    fn test_from_args_unshare_all() -> Result<()> {
        let mut args = create_minimal_args();
        args.unshare_all = true;

        let config = SandboxConfig::from_args(&args)?;

        assert!(config.unshare_user);
        assert!(config.unshare_pid);
        assert!(config.unshare_net);
        assert!(config.unshare_ipc);
        assert!(config.unshare_uts);
        assert!(config.unshare_cgroup);

        Ok(())
    }

    #[test]
    fn test_from_args_unshare_all_with_share_net() -> Result<()> {
        let mut args = create_minimal_args();
        args.unshare_all = true;
        args.share_net = true;

        let config = SandboxConfig::from_args(&args)?;

        assert!(config.unshare_user);
        assert!(config.unshare_pid);
        assert!(!config.unshare_net); // Should be false due to share_net
        assert!(config.unshare_ipc);
        assert!(config.unshare_uts);
        assert!(config.unshare_cgroup);

        Ok(())
    }

    #[test]
    fn test_from_args_share_net_without_unshare_all() -> Result<()> {
        let mut args = create_minimal_args();
        args.unshare_net = true;
        args.share_net = true; // This should override unshare_net

        let config = SandboxConfig::from_args(&args)?;

        assert!(!config.unshare_net); // Should be false due to share_net

        Ok(())
    }

    #[test]
    fn test_from_args_share_net_alone() -> Result<()> {
        let mut args = create_minimal_args();
        args.share_net = true;

        let config = SandboxConfig::from_args(&args)?;

        assert!(!config.unshare_net); // Should remain false

        Ok(())
    }

    #[test]
    fn test_from_args_individual_namespaces() -> Result<()> {
        let mut args = create_minimal_args();
        args.unshare_user = true;
        args.unshare_pid = true;

        let config = SandboxConfig::from_args(&args)?;

        assert!(config.unshare_user);
        assert!(config.unshare_pid);
        assert!(!config.unshare_net);
        assert!(!config.unshare_ipc);

        Ok(())
    }

    #[test]
    fn test_from_args_environment() -> Result<()> {
        let mut args = create_minimal_args();
        args.clearenv = true;
        args.setenv = vec![
            "FOO".to_string(),
            "bar".to_string(),
            "BAZ".to_string(),
            "qux".to_string(),
        ];
        args.unsetenv = vec!["OLDVAR".to_string()];

        let config = SandboxConfig::from_args(&args)?;

        assert!(config.clearenv);
        assert_eq!(config.setenv.len(), 2);
        assert_eq!(config.setenv[0], ("FOO".to_string(), "bar".to_string()));
        assert_eq!(config.setenv[1], ("BAZ".to_string(), "qux".to_string()));
        assert_eq!(config.unsetenv, vec!["OLDVAR"]);

        Ok(())
    }

    #[test]
    fn test_from_args_uid_gid() -> Result<()> {
        let mut args = create_minimal_args();
        args.uid = Some(1000);
        args.gid = Some(1000);

        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.sandbox_uid, Some(Uid::from_raw(1000)));
        assert_eq!(config.sandbox_gid, Some(Gid::from_raw(1000)));

        Ok(())
    }

    #[test]
    fn test_from_args_hostname_chdir() -> Result<()> {
        let mut args = create_minimal_args();
        args.hostname = Some("sandbox".to_string());
        args.chdir = Some(PathBuf::from("/workdir"));

        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.hostname, Some("sandbox".to_string()));
        assert_eq!(config.chdir, Some(PathBuf::from("/workdir")));

        Ok(())
    }

    #[test]
    fn test_from_args_process_flags() -> Result<()> {
        let mut args = create_minimal_args();
        args.new_session = true;
        args.die_with_parent = true;

        let config = SandboxConfig::from_args(&args)?;

        assert!(config.new_session);
        assert!(config.die_with_parent);

        Ok(())
    }

    #[test]
    fn test_from_args_capabilities() -> Result<()> {
        let mut args = create_minimal_args();
        args.cap_add = vec!["NET_ADMIN".to_string(), "SYS_PTRACE".to_string()];
        args.cap_drop = vec!["SYS_ADMIN".to_string()];

        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.cap_add, vec!["NET_ADMIN", "SYS_PTRACE"]);
        assert_eq!(config.cap_drop, vec!["SYS_ADMIN"]);

        Ok(())
    }

    #[test]
    fn test_from_args_seccomp() -> Result<()> {
        let mut args = create_minimal_args();
        args.seccomp = Some(3);

        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.seccomp_fd, Some(3));

        Ok(())
    }

    #[test]
    fn test_from_args_complex_scenario() -> Result<()> {
        let mut args = create_minimal_args();
        args.unshare_all = true;
        args.bind = vec!["/host/src".to_string(), "/container/dst".to_string()];
        args.ro_bind = vec!["/etc".to_string(), "/etc".to_string()];
        args.proc = vec![PathBuf::from("/proc")];
        args.dev = vec![PathBuf::from("/dev")];
        args.tmpfs = vec![PathBuf::from("/tmp")];
        args.dir = vec![PathBuf::from("/workdir")];
        args.setenv = vec!["PATH".to_string(), "/usr/bin".to_string()];
        args.uid = Some(1000);
        args.gid = Some(1000);
        args.hostname = Some("container".to_string());
        args.chdir = Some(PathBuf::from("/workdir"));
        args.command = vec![
            "bash".to_string(),
            "-c".to_string(),
            "echo hello".to_string(),
        ];

        let config = SandboxConfig::from_args(&args)?;

        // Verify namespaces
        assert!(config.unshare_user);
        assert!(config.unshare_pid);
        assert!(config.unshare_net);

        // Verify setup operations
        assert_eq!(config.setup_ops.len(), 6); // 1 bind + 1 ro_bind + proc + dev + tmpfs + dir

        // Verify environment
        assert_eq!(config.setenv.len(), 1);
        assert_eq!(
            config.setenv[0],
            ("PATH".to_string(), "/usr/bin".to_string())
        );

        // Verify identity
        assert_eq!(config.sandbox_uid, Some(Uid::from_raw(1000)));
        assert_eq!(config.sandbox_gid, Some(Gid::from_raw(1000)));

        // Verify other settings
        assert_eq!(config.hostname, Some("container".to_string()));
        assert_eq!(config.chdir, Some(PathBuf::from("/workdir")));
        assert_eq!(config.command, vec!["bash", "-c", "echo hello"]);

        Ok(())
    }

    #[test]
    fn test_from_args_multiple_bind_mounts() -> Result<()> {
        let mut args = create_minimal_args();
        args.bind = vec![
            "/src1".to_string(),
            "/dst1".to_string(),
            "/src2".to_string(),
            "/dst2".to_string(),
            "/src3".to_string(),
            "/dst3".to_string(),
        ];

        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.setup_ops.len(), 3);
        for op in &config.setup_ops {
            assert!(matches!(op, SetupOp::BindMount { .. }));
        }

        Ok(())
    }

    #[test]
    fn test_from_args_mixed_bind_mount_types() -> Result<()> {
        let mut args = create_minimal_args();
        args.bind = vec!["/rw/src".to_string(), "/rw/dst".to_string()];
        args.ro_bind = vec!["/ro/src".to_string(), "/ro/dst".to_string()];
        args.dev_bind = vec!["/dev/src".to_string(), "/dev/dst".to_string()];
        args.bind_try = vec!["/try/src".to_string(), "/try/dst".to_string()];

        let config = SandboxConfig::from_args(&args)?;

        assert_eq!(config.setup_ops.len(), 4);

        // First should be regular bind (not readonly, not devices)
        match &config.setup_ops[0] {
            SetupOp::BindMount {
                readonly, devices, ..
            } => {
                assert!(!readonly);
                assert!(!devices);
            }
            _ => panic!("Expected BindMount"),
        }

        // Second should be readonly bind
        match &config.setup_ops[1] {
            SetupOp::BindMount {
                readonly, devices, ..
            } => {
                assert!(readonly);
                assert!(!devices);
            }
            _ => panic!("Expected BindMount"),
        }

        // Third should be BindMountTry (bind_try is processed before dev_bind)
        match &config.setup_ops[2] {
            SetupOp::BindMountTry {
                readonly, devices, ..
            } => {
                assert!(!readonly);
                assert!(!devices);
            }
            _ => panic!("Expected BindMountTry"),
        }

        // Fourth should be dev bind (devices=true)
        match &config.setup_ops[3] {
            SetupOp::BindMount {
                readonly, devices, ..
            } => {
                assert!(!readonly);
                assert!(devices);
            }
            _ => panic!("Expected BindMount"),
        }

        Ok(())
    }
}
