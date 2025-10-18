//! Filesystem mount operations

use eyre::{Context, Result};
use nix::mount::{MntFlags, MsFlags, mount, umount2};
use std::path::Path;

/// Mount proc filesystem
pub fn mount_proc<P: AsRef<Path>>(target: P) -> Result<()> {
    log::debug!("Mounting proc filesystem at {}", target.as_ref().display());
    mount(
        Some("proc"),
        target.as_ref(),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .wrap_err_with(|| format!("Failed to mount proc on {}", target.as_ref().display()))?;
    log::debug!("Successfully mounted proc filesystem");

    Ok(())
}

/// Mount tmpfs filesystem
pub fn mount_tmpfs<P: AsRef<Path>>(target: P, mode: u32, size: Option<usize>) -> Result<()> {
    let options = if let Some(s) = size {
        format!("mode={:o},size={}", mode, s)
    } else {
        format!("mode={:o}", mode)
    };

    log::debug!(
        "Mounting tmpfs at {} with options: {}",
        target.as_ref().display(),
        options
    );
    mount(
        Some("tmpfs"),
        target.as_ref(),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(options.as_str()),
    )
    .wrap_err_with(|| format!("Failed to mount tmpfs on {}", target.as_ref().display()))?;
    log::debug!("Successfully mounted tmpfs");

    Ok(())
}

/// Mount devpts filesystem
pub fn mount_devpts<P: AsRef<Path>>(target: P) -> Result<()> {
    log::debug!("Mounting devpts at {}", target.as_ref().display());
    mount(
        Some("devpts"),
        target.as_ref(),
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=620"),
    )
    .wrap_err_with(|| format!("Failed to mount devpts on {}", target.as_ref().display()))?;
    log::debug!("Successfully mounted devpts");

    Ok(())
}

/// Mount mqueue filesystem
pub fn mount_mqueue<P: AsRef<Path>>(target: P) -> Result<()> {
    log::debug!("Mounting mqueue at {}", target.as_ref().display());
    mount(
        Some("mqueue"),
        target.as_ref(),
        Some("mqueue"),
        MsFlags::empty(),
        None::<&str>,
    )
    .wrap_err_with(|| format!("Failed to mount mqueue on {}", target.as_ref().display()))?;
    log::debug!("Successfully mounted mqueue");

    Ok(())
}

/// Remount filesystem as read-only
pub fn remount_ro<P: AsRef<Path>>(target: P) -> Result<()> {
    log::debug!("Remounting {} as read-only", target.as_ref().display());
    mount(
        None::<&str>,
        target.as_ref(),
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .wrap_err_with(|| {
        format!(
            "Failed to remount {} as read-only",
            target.as_ref().display()
        )
    })?;
    log::debug!("Successfully remounted as read-only");

    Ok(())
}

/// Make mount point private (don't propagate mounts)
pub fn make_private<P: AsRef<Path>>(target: P) -> Result<()> {
    log::debug!("Making {} private", target.as_ref().display());
    mount(
        None::<&str>,
        target.as_ref(),
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .wrap_err_with(|| format!("Failed to make {} private", target.as_ref().display()))?;
    log::debug!("Successfully made mount private");

    Ok(())
}

/// Make mount point slave (receive but don't propagate)
pub fn make_slave<P: AsRef<Path>>(target: P) -> Result<()> {
    log::debug!("Making {} slave", target.as_ref().display());
    mount(
        None::<&str>,
        target.as_ref(),
        None::<&str>,
        MsFlags::MS_SLAVE | MsFlags::MS_REC,
        None::<&str>,
    )
    .wrap_err_with(|| format!("Failed to make {} slave", target.as_ref().display()))?;
    log::debug!("Successfully made mount slave");

    Ok(())
}

/// Unmount filesystem
pub fn unmount<P: AsRef<Path>>(target: P, detach: bool) -> Result<()> {
    let flags = if detach {
        MntFlags::MNT_DETACH
    } else {
        MntFlags::empty()
    };

    umount2(target.as_ref(), flags)
        .wrap_err_with(|| format!("Failed to unmount {}", target.as_ref().display()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_tmpfs_options_formatting() {
        // Test option string formatting without size
        let without_size = format!("mode={:o}", 0o755);
        assert_eq!(without_size, "mode=755");

        // Test with size
        let with_size = format!("mode={:o},size={}", 0o755, 1024);
        assert_eq!(with_size, "mode=755,size=1024");
    }

    #[test]
    fn test_tmpfs_options_various_modes() {
        // Test different permission modes
        let options_755 = format!("mode={:o}", 0o755);
        assert_eq!(options_755, "mode=755");

        let options_1777 = format!("mode={:o}", 0o1777);
        assert_eq!(options_1777, "mode=1777");

        let options_644 = format!("mode={:o}", 0o644);
        assert_eq!(options_644, "mode=644");
    }

    #[test]
    fn test_tmpfs_options_with_various_sizes() {
        // Test size formatting
        let kb = format!("mode={:o},size={}", 0o755, 1024);
        assert_eq!(kb, "mode=755,size=1024");

        let mb = format!("mode={:o},size={}", 0o755, 1024 * 1024);
        assert_eq!(mb, "mode=755,size=1048576");

        let gb = format!("mode={:o},size={}", 0o755, 1024 * 1024 * 1024);
        assert_eq!(gb, "mode=755,size=1073741824");
    }

    #[test]
    fn test_mount_proc_nonexistent_target() {
        // Mounting to nonexistent directory should fail
        let result = mount_proc("/nonexistent/proc/mount/point");
        assert!(result.is_err());
    }

    #[test]
    fn test_mount_proc_needs_privileges() {
        // Mounting proc without privileges should fail (unless we're root)
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("proc");
        std::fs::create_dir(&target).unwrap();

        let result = mount_proc(&target);
        // Will fail with EPERM unless running as root
        if nix::unistd::getuid().as_raw() != 0 {
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("Operation not permitted") || err_msg.contains("Failed to mount")
            );
        }
    }

    #[test]
    fn test_mount_tmpfs_nonexistent_target() {
        // Mounting to nonexistent directory should fail
        let result = mount_tmpfs("/nonexistent/tmpfs/mount/point", 0o755, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_mount_tmpfs_needs_privileges() {
        // Mounting tmpfs without privileges should fail (unless we're root)
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("tmpfs");
        std::fs::create_dir(&target).unwrap();

        let result = mount_tmpfs(&target, 0o755, None);
        // Will fail with EPERM unless running as root
        if nix::unistd::getuid().as_raw() != 0 {
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("Operation not permitted") || err_msg.contains("Failed to mount")
            );
        }
    }

    #[test]
    fn test_mount_tmpfs_with_size() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("tmpfs");
        std::fs::create_dir(&target).unwrap();

        let result = mount_tmpfs(&target, 0o1777, Some(1024 * 1024));
        // Will fail with EPERM unless running as root
        if nix::unistd::getuid().as_raw() != 0 {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_mount_devpts_nonexistent_target() {
        let result = mount_devpts("/nonexistent/devpts/mount/point");
        assert!(result.is_err());
    }

    #[test]
    fn test_mount_devpts_needs_privileges() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("pts");
        std::fs::create_dir(&target).unwrap();

        let result = mount_devpts(&target);
        if nix::unistd::getuid().as_raw() != 0 {
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("Operation not permitted") || err_msg.contains("Failed to mount")
            );
        }
    }

    #[test]
    fn test_mount_mqueue_nonexistent_target() {
        let result = mount_mqueue("/nonexistent/mqueue/mount/point");
        assert!(result.is_err());
    }

    #[test]
    fn test_mount_mqueue_needs_privileges() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("mqueue");
        std::fs::create_dir(&target).unwrap();

        let result = mount_mqueue(&target);
        if nix::unistd::getuid().as_raw() != 0 {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_remount_ro_nonexistent_target() {
        let result = remount_ro("/nonexistent/mount/point");
        assert!(result.is_err());
    }

    #[test]
    fn test_remount_ro_not_mounted() {
        // Trying to remount a directory that isn't a mount point should fail
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("notmounted");
        std::fs::create_dir(&target).unwrap();

        let result = remount_ro(&target);
        assert!(result.is_err());
    }

    #[test]
    fn test_make_private_nonexistent_target() {
        let result = make_private("/nonexistent/mount/point");
        assert!(result.is_err());
    }

    #[test]
    fn test_make_private_not_mounted() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("notmounted");
        std::fs::create_dir(&target).unwrap();

        let result = make_private(&target);
        assert!(result.is_err());
    }

    #[test]
    fn test_make_slave_nonexistent_target() {
        let result = make_slave("/nonexistent/mount/point");
        assert!(result.is_err());
    }

    #[test]
    fn test_make_slave_not_mounted() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("notmounted");
        std::fs::create_dir(&target).unwrap();

        let result = make_slave(&target);
        assert!(result.is_err());
    }

    #[test]
    fn test_unmount_nonexistent_target() {
        let result = unmount("/nonexistent/mount/point", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_unmount_not_mounted() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("notmounted");
        std::fs::create_dir(&target).unwrap();

        let result = unmount(&target, false);
        assert!(result.is_err());
    }

    #[test]
    fn test_unmount_with_detach_flag() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join("notmounted");
        std::fs::create_dir(&target).unwrap();

        // Even with detach flag, unmounting non-mounted directory should fail
        let result = unmount(&target, true);
        assert!(result.is_err());
    }
}
