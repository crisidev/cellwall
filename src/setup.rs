//! Sandbox setup operations

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use eyre::Result;

use crate::bind_mount::{BindMountFlags, bind_mount};
use crate::mount::{mount_devpts, mount_proc, mount_tmpfs, remount_ro};
use crate::utils::{create_parent_dirs, ensure_dir, ensure_file};

/// Setup operation types
#[derive(Debug, Clone)]
pub(crate) enum SetupOp {
    BindMount {
        source: PathBuf,
        dest: PathBuf,
        readonly: bool,
        devices: bool,
        recursive: bool,
    },
    MountProc {
        dest: PathBuf,
    },
    MountDev {
        dest: PathBuf,
    },
    MountTmpfs {
        dest: PathBuf,
        mode: u32,
        size: Option<usize>,
    },
    CreateDir {
        path: PathBuf,
        mode: u32,
    },
    CreateSymlink {
        source: String,
        dest: PathBuf,
    },
    RemountRo {
        path: PathBuf,
    },
    Chmod {
        path: PathBuf,
        mode: u32,
    },
    BindMountTry {
        source: PathBuf,
        dest: PathBuf,
        readonly: bool,
        devices: bool,
        recursive: bool,
    },
    BindMountFd {
        fd: i32,
        dest: PathBuf,
        readonly: bool,
    },
}

/// Execute a setup operation
pub(crate) fn execute_setup_op(op: &SetupOp) -> Result<()> {
    match op {
        SetupOp::BindMount {
            source,
            dest,
            readonly,
            devices,
            recursive,
        } => {
            log::debug!("Bind mounting {} to {}", source.display(), dest.display());

            // Ensure parent directories exist
            create_parent_dirs(dest, 0o755)?;

            // Create the destination if it doesn't exist
            // Follow symlinks to check the real target
            if !dest.exists() {
                if source.is_dir() {
                    ensure_dir(dest, 0o755)?;
                } else {
                    ensure_file(dest, 0o644)?;
                }
            }

            let mut flags = BindMountFlags::empty();
            if *readonly {
                flags |= BindMountFlags::READONLY;
            }
            if *devices {
                flags |= BindMountFlags::DEVICES;
            }
            if *recursive {
                flags |= BindMountFlags::RECURSIVE;
            }

            bind_mount(source, dest, flags)?;
        }

        SetupOp::MountProc { dest } => {
            log::debug!("Mounting proc at {}", dest.display());
            ensure_dir(dest, 0o755)?;
            mount_proc(dest)?;
        }

        SetupOp::MountDev { dest } => {
            log::debug!("Mounting dev at {}", dest.display());
            setup_dev_filesystem(dest)?;
        }

        SetupOp::MountTmpfs { dest, mode, size } => {
            log::debug!("Mounting tmpfs at {}", dest.display());
            ensure_dir(dest, 0o755)?;
            mount_tmpfs(dest, *mode, *size)?;
        }

        SetupOp::CreateDir { path, mode } => {
            log::debug!("Creating directory {}", path.display());
            create_parent_dirs(path, 0o755)?;
            ensure_dir(path, *mode)?;
        }

        SetupOp::CreateSymlink { source, dest } => {
            log::debug!("Creating symlink {} -> {}", dest.display(), source);
            create_parent_dirs(dest, 0o755)?;

            // Check if symlink already exists with correct target
            if (dest.is_symlink() || dest.exists())
                && let Ok(target) = fs::read_link(dest)
                && target == Path::new(source)
            {
                // Already exists with correct target
                return Ok(());
            }

            // Try to create, ignore if already exists
            if let Err(e) = symlink(source, dest)
                && e.kind() != std::io::ErrorKind::AlreadyExists
            {
                return Err(e.into());
            }
        }

        SetupOp::RemountRo { path } => {
            log::debug!("Remounting {} as read-only", path.display());
            remount_ro(path)?;
        }

        SetupOp::Chmod { path, mode } => {
            log::debug!("Changing permissions of {} to {:o}", path.display(), mode);
            fs::set_permissions(path, std::fs::Permissions::from_mode(*mode))?;
        }

        SetupOp::BindMountTry {
            source,
            dest,
            readonly,
            devices,
            recursive,
        } => {
            // Check if source exists, skip if not
            if !source.exists() {
                log::debug!(
                    "Skipping bind mount of {} (source doesn't exist)",
                    source.display()
                );
                return Ok(());
            }

            log::debug!("Bind mounting {} to {}", source.display(), dest.display());

            // Ensure parent directories exist
            create_parent_dirs(dest, 0o755)?;

            // Create the destination if it doesn't exist
            if !dest.exists() {
                if source.is_dir() {
                    ensure_dir(dest, 0o755)?;
                } else {
                    ensure_file(dest, 0o644)?;
                }
            }

            let mut flags = BindMountFlags::empty();
            if *readonly {
                flags |= BindMountFlags::READONLY;
            }
            if *devices {
                flags |= BindMountFlags::DEVICES;
            }
            if *recursive {
                flags |= BindMountFlags::RECURSIVE;
            }

            bind_mount(source, dest, flags)?;
        }

        SetupOp::BindMountFd { fd, dest, readonly } => {
            log::debug!("Bind mounting from FD {} to {}", fd, dest.display());

            // Construct path to /proc/self/fd/<fd> and resolve it to the actual path
            let fd_path = format!("/proc/self/fd/{}", fd);

            // Resolve the symlink to get the actual path
            // This is necessary because bind mount doesn't work with /proc/self/fd symlinks
            let source = std::fs::read_link(&fd_path)
                .map_err(|e| eyre::eyre!("Failed to resolve FD {}: {}", fd, e))?;

            log::debug!("FD {} resolves to: {}", fd, source.display());

            // Get stat info from the FD before mounting
            // This is used to detect race conditions after the mount
            // We use the original fd_path for fstat to avoid TOCTOU issues
            let fd_stat = {
                let metadata = std::fs::metadata(&fd_path)
                    .map_err(|e| eyre::eyre!("Failed to stat FD {}: {}", fd, e))?;
                (metadata.dev(), metadata.ino())
            };

            // Ensure parent directories exist
            create_parent_dirs(dest, 0o755)?;

            // Create the destination if it doesn't exist
            if !dest.exists() {
                if source.is_dir() {
                    ensure_dir(dest, 0o755)?;
                } else {
                    ensure_file(dest, 0o644)?;
                }
            }

            let mut flags = BindMountFlags::RECURSIVE;
            if *readonly {
                flags |= BindMountFlags::READONLY;
            }

            bind_mount(&source, dest, flags)?;

            // Verify that what we mounted is what we intended (race condition detection)
            // This matches bubblewrap's implementation - see bubblewrap.c lines 1266-1273
            let mount_stat = {
                let metadata = std::fs::metadata(dest).map_err(|e| {
                    eyre::eyre!("Failed to stat mount at {}: {}", dest.display(), e)
                })?;
                (metadata.dev(), metadata.ino())
            };

            if fd_stat != mount_stat {
                eyre::bail!(
                    "Race condition detected: FD {} changed between stat and mount",
                    fd
                );
            }

            log::debug!("FD-based bind mount successful and verified");
        }
    }

    Ok(())
}

/// Setup a complete /dev filesystem
fn setup_dev_filesystem<P: AsRef<Path>>(dest: P) -> Result<()> {
    let dest = dest.as_ref();

    log::debug!("Setting up complete /dev filesystem at {}", dest.display());

    ensure_dir(dest, 0o755)?;
    log::debug!("Mounting tmpfs for /dev");
    mount_tmpfs(dest, 0o755, None)?;

    // Create standard device nodes by bind-mounting from host
    let dev_nodes = ["null", "zero", "full", "random", "urandom", "tty"];

    log::debug!("Creating device nodes: {:?}", dev_nodes);
    for node in &dev_nodes {
        let node_dest = dest.join(node);
        let node_src = PathBuf::from("/dev").join(node);

        log::debug!("Bind mounting device node: /dev/{}", node);
        ensure_file(&node_dest, 0o644)?;

        bind_mount(
            &node_src,
            &node_dest,
            BindMountFlags::DEVICES | BindMountFlags::RECURSIVE,
        )?;
    }

    // Create /dev/pts for pseudo-terminals
    let pts_dir = dest.join("pts");
    log::debug!("Creating /dev/pts for pseudo-terminals");
    ensure_dir(&pts_dir, 0o755)?;
    mount_devpts(&pts_dir)?;

    // Create /dev/ptmx symlink
    let ptmx = dest.join("ptmx");
    log::debug!("Creating /dev/ptmx symlink");
    symlink("pts/ptmx", &ptmx)?;

    // Create /dev/shm
    let shm = dest.join("shm");
    log::debug!("Creating /dev/shm directory");
    ensure_dir(&shm, 0o755)?;

    // Create standard fd symlinks
    log::debug!("Creating standard fd symlinks (stdin, stdout, stderr, fd)");
    let stdin = dest.join("stdin");
    symlink("/proc/self/fd/0", &stdin)?;

    let stdout = dest.join("stdout");
    symlink("/proc/self/fd/1", &stdout)?;

    let stderr = dest.join("stderr");
    symlink("/proc/self/fd/2", &stderr)?;

    // Create /dev/fd symlink
    let fd = dest.join("fd");
    symlink("/proc/self/fd", &fd)?;

    log::debug!("/dev filesystem setup complete");

    Ok(())
}
