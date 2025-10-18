//! Sandbox setup operations

use crate::bind_mount::{BindMountFlags, bind_mount};
use crate::mount::{mount_devpts, mount_proc, mount_tmpfs, remount_ro};
use crate::utils::{create_parent_dirs, ensure_dir, ensure_file};
use eyre::Result;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

/// Setup operation types
#[derive(Debug, Clone)]
pub enum SetupOp {
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
    CreateFile {
        path: PathBuf,
        mode: u32,
        contents: Vec<u8>,
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
}

/// Execute a setup operation
pub fn execute_setup_op(op: &SetupOp) -> Result<()> {
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

        SetupOp::CreateFile {
            path,
            mode,
            contents,
        } => {
            log::debug!("Creating file {}", path.display());
            create_parent_dirs(path, 0o755)?;
            fs::write(path, contents)?;
            fs::set_permissions(path, std::fs::Permissions::from_mode(*mode))?;
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
    }

    Ok(())
}

/// Setup a complete /dev filesystem
fn setup_dev_filesystem<P: AsRef<Path>>(dest: P) -> Result<()> {
    let dest = dest.as_ref();

    ensure_dir(dest, 0o755)?;
    mount_tmpfs(dest, 0o755, None)?;

    // Create standard device nodes by bind-mounting from host
    let dev_nodes = ["null", "zero", "full", "random", "urandom", "tty"];

    for node in &dev_nodes {
        let node_dest = dest.join(node);
        let node_src = PathBuf::from("/dev").join(node);

        ensure_file(&node_dest, 0o644)?;

        bind_mount(
            &node_src,
            &node_dest,
            BindMountFlags::DEVICES | BindMountFlags::RECURSIVE,
        )?;
    }

    // Create /dev/pts for pseudo-terminals
    let pts_dir = dest.join("pts");
    ensure_dir(&pts_dir, 0o755)?;
    mount_devpts(&pts_dir)?;

    // Create /dev/ptmx symlink
    let ptmx = dest.join("ptmx");
    symlink("pts/ptmx", &ptmx)?;

    // Create /dev/shm
    let shm = dest.join("shm");
    ensure_dir(&shm, 0o755)?;

    // Create standard fd symlinks
    let stdin = dest.join("stdin");
    symlink("/proc/self/fd/0", &stdin)?;

    let stdout = dest.join("stdout");
    symlink("/proc/self/fd/1", &stdout)?;

    let stderr = dest.join("stderr");
    symlink("/proc/self/fd/2", &stderr)?;

    // Create /dev/fd symlink
    let fd = dest.join("fd");
    symlink("/proc/self/fd", &fd)?;

    Ok(())
}

use std::os::unix::fs::PermissionsExt;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_op_creation() {
        let op = SetupOp::CreateDir {
            path: PathBuf::from("/tmp/test"),
            mode: 0o755,
        };

        match op {
            SetupOp::CreateDir { path, mode } => {
                assert_eq!(path, PathBuf::from("/tmp/test"));
                assert_eq!(mode, 0o755);
            }
            _ => panic!("Wrong variant"),
        }
    }
}
