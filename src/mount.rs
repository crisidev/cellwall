//! Filesystem mount operations

use eyre::{Context, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use std::path::Path;

/// Mount proc filesystem
pub fn mount_proc<P: AsRef<Path>>(target: P) -> Result<()> {
    mount(
        Some("proc"),
        target.as_ref(),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC | MsFlags::MS_NODEV,
        None::<&str>,
    )
    .wrap_err_with(|| format!("Failed to mount proc on {}", target.as_ref().display()))?;

    Ok(())
}

/// Mount tmpfs filesystem
pub fn mount_tmpfs<P: AsRef<Path>>(target: P, mode: u32, size: Option<usize>) -> Result<()> {
    let options = if let Some(s) = size {
        format!("mode={:o},size={}", mode, s)
    } else {
        format!("mode={:o}", mode)
    };

    mount(
        Some("tmpfs"),
        target.as_ref(),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some(options.as_str()),
    )
    .wrap_err_with(|| format!("Failed to mount tmpfs on {}", target.as_ref().display()))?;

    Ok(())
}

/// Mount devpts filesystem
pub fn mount_devpts<P: AsRef<Path>>(target: P) -> Result<()> {
    mount(
        Some("devpts"),
        target.as_ref(),
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=620"),
    )
    .wrap_err_with(|| format!("Failed to mount devpts on {}", target.as_ref().display()))?;

    Ok(())
}

/// Mount mqueue filesystem
pub fn mount_mqueue<P: AsRef<Path>>(target: P) -> Result<()> {
    mount(
        Some("mqueue"),
        target.as_ref(),
        Some("mqueue"),
        MsFlags::empty(),
        None::<&str>,
    )
    .wrap_err_with(|| format!("Failed to mount mqueue on {}", target.as_ref().display()))?;

    Ok(())
}

/// Remount filesystem as read-only
pub fn remount_ro<P: AsRef<Path>>(target: P) -> Result<()> {
    mount(
        None::<&str>,
        target.as_ref(),
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
        None::<&str>,
    )
    .wrap_err_with(|| format!("Failed to remount {} as read-only", target.as_ref().display()))?;

    Ok(())
}

/// Make mount point private (don't propagate mounts)
pub fn make_private<P: AsRef<Path>>(target: P) -> Result<()> {
    mount(
        None::<&str>,
        target.as_ref(),
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .wrap_err_with(|| format!("Failed to make {} private", target.as_ref().display()))?;

    Ok(())
}

/// Make mount point slave (receive but don't propagate)
pub fn make_slave<P: AsRef<Path>>(target: P) -> Result<()> {
    mount(
        None::<&str>,
        target.as_ref(),
        None::<&str>,
        MsFlags::MS_SLAVE | MsFlags::MS_REC,
        None::<&str>,
    )
    .wrap_err_with(|| format!("Failed to make {} slave", target.as_ref().display()))?;

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

    #[test]
    fn test_tmpfs_options() {
        // Just test option string formatting
        let with_size = format!("mode={:o},size={}", 0o755, 1024);
        assert_eq!(with_size, "mode=755,size=1024");

        let without_size = format!("mode={:o}", 0o755);
        assert_eq!(without_size, "mode=755");
    }
}
