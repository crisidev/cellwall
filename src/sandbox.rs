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
            unshare_net = !args.share_net;
            unshare_ipc = true;
            unshare_uts = true;
            unshare_cgroup = true;
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
}

/// Run the sandbox
pub fn run_sandbox(config: SandboxConfig) -> Result<()> {
    log::info!("Starting sandbox setup");

    let real_uid = getuid();
    let real_gid = getgid();

    let sandbox_uid = config.sandbox_uid.unwrap_or(real_uid);
    let sandbox_gid = config.sandbox_gid.unwrap_or(real_gid);

    // Build namespace flags
    let mut clone_flags = CloneFlags::empty();

    // Check if we're trying to mount proc (requires PID namespace)
    let needs_proc = config
        .setup_ops
        .iter()
        .any(|op| matches!(op, SetupOp::MountProc { .. }));

    // Only create mount namespace if we have setup operations that need it
    let needs_mount_ns = !config.setup_ops.is_empty()
        || config.unshare_user
        || config.unshare_pid
        || config.unshare_net
        || config.unshare_ipc
        || config.unshare_uts
        || config.unshare_cgroup;

    // If we need mount namespace but not running as root, we need user namespace
    let mut needs_user_ns = config.unshare_user;
    if needs_mount_ns && real_uid != Uid::from_raw(0) {
        needs_user_ns = true;
    }

    // Mounting proc requires PID namespace
    let mut needs_pid_ns = config.unshare_pid;
    if needs_proc {
        needs_pid_ns = true;
    }

    if needs_mount_ns {
        clone_flags |= CloneFlags::CLONE_NEWNS;
    }

    if needs_user_ns {
        clone_flags |= CloneFlags::CLONE_NEWUSER;
    }
    if needs_pid_ns {
        clone_flags |= CloneFlags::CLONE_NEWPID;
    }
    if config.unshare_net {
        clone_flags |= CloneFlags::CLONE_NEWNET;
    }
    if config.unshare_ipc {
        clone_flags |= CloneFlags::CLONE_NEWIPC;
    }
    if config.unshare_uts {
        clone_flags |= CloneFlags::CLONE_NEWUTS;
    }
    if config.unshare_cgroup {
        clone_flags |= CloneFlags::CLONE_NEWCGROUP;
    }

    // Only unshare if we have namespaces to create
    if !clone_flags.is_empty() {
        log::debug!("Unsharing namespaces: {:?}", clone_flags);
        unshare_namespaces(clone_flags)?;

        // If we created a PID namespace, we need to fork so the child enters it
        if needs_pid_ns {
            match unsafe { fork() }? {
                ForkResult::Parent { child } => {
                    // Parent: wait for child and exit with its status
                    match waitpid(child, None)? {
                        WaitStatus::Exited(_, status) => std::process::exit(status),
                        WaitStatus::Signaled(_, sig, _) => std::process::exit(128 + sig as i32),
                        _ => std::process::exit(1),
                    }
                }
                ForkResult::Child => {
                    // Child continues with the sandbox setup
                }
            }
        }
    }

    // Setup user namespace mappings if needed
    if needs_user_ns {
        log::debug!(
            "Setting up user namespace: uid={}, gid={}",
            sandbox_uid,
            sandbox_gid
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
    }

    // Setup network namespace
    if config.unshare_net {
        log::debug!("Setting up loopback interface");
        setup_loopback().wrap_err("Failed to setup loopback interface")?;
    }

    // Make root mount slave to prevent propagation (only if we have mount namespace)
    if needs_mount_ns {
        make_slave("/")?;
    }

    // Execute all setup operations
    log::info!("Executing {} setup operations", config.setup_ops.len());
    for op in &config.setup_ops {
        execute_setup_op(op)?;
    }

    // Set hostname if requested
    if let Some(hostname) = &config.hostname {
        nix::unistd::sethostname(hostname)?;
    }

    // Setup die-with-parent (before changing directory/session)
    if config.die_with_parent {
        set_pdeathsig(libc::SIGKILL)?;
    }

    // Create new session if requested
    if config.new_session {
        setsid()?;
    }

    // Change directory if requested
    if let Some(dir) = &config.chdir {
        chdir(dir.as_path())?;
    }

    // Setup environment variables
    if config.clearenv {
        std::env::vars().for_each(|(key, _)| unsafe {
            std::env::remove_var(&key);
        });
        // Keep PWD
        if let Ok(pwd) = std::env::current_dir() {
            unsafe {
                std::env::set_var("PWD", pwd);
            }
        }
    }

    for var in &config.unsetenv {
        unsafe {
            std::env::remove_var(var);
        }
    }

    for (var, value) in &config.setenv {
        unsafe {
            std::env::set_var(var, value);
        }
    }

    // Log what we're about to execute BEFORE loading seccomp
    // (logging after seccomp can cause issues)
    log::info!("Executing command: {:?}", config.command);

    // Apply capability changes (only for root)
    if real_uid == Uid::from_raw(0) && (!config.cap_add.is_empty() || !config.cap_drop.is_empty()) {
        log::debug!(
            "Applying capability changes: add={:?}, drop={:?}",
            config.cap_add,
            config.cap_drop
        );
        apply_capability_changes(&config.cap_add, &config.cap_drop)?;
    }

    // Drop privileges before loading seccomp (if not root)
    if real_uid != Uid::from_raw(0) {
        drop_all_caps()?;
    } else if needs_user_ns {
        // Set ambient capabilities for unprivileged execution
        set_ambient_capabilities()?;
    }

    // Apply seccomp filter if provided
    // IMPORTANT: This must be the LAST thing we do before exec!
    // After loading seccomp, we cannot safely do any Rust operations
    // (logging, error handling, etc.) as they may trigger syscalls or
    // memory operations that could conflict with the filter
    if let Some(fd) = config.seccomp_fd {
        load_seccomp_from_fd(fd)?;
    }

    // Execute the command immediately after seccomp
    exec_command(&config.command)?;

    Ok(())
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
    let err = cmd.exec();

    // exec only returns if there's an error
    Err(err.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sandbox_config_basic() {
        let config = SandboxConfig {
            command: vec!["bash".to_string()],
            setup_ops: vec![],
            unshare_user: true,
            unshare_pid: false,
            unshare_net: false,
            unshare_ipc: false,
            unshare_uts: false,
            unshare_cgroup: false,
            sandbox_uid: None,
            sandbox_gid: None,
            hostname: None,
            chdir: None,
            new_session: false,
            die_with_parent: false,
            clearenv: false,
            setenv: vec![],
            unsetenv: vec![],
            cap_add: vec![],
            cap_drop: vec![],
            seccomp_fd: None,
        };

        assert!(config.unshare_user);
        assert!(!config.unshare_pid);
        assert_eq!(config.command, vec!["bash"]);
    }
}
