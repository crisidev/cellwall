//! Bind mount operations

use eyre::{Context, Result};
use nix::mount::{MsFlags, mount};
use std::path::Path;

bitflags::bitflags! {
    /// Bind mount flags
    #[derive(Debug)]
    pub struct BindMountFlags: u32 {
        const READONLY = 1 << 0;
        const DEVICES = 1 << 1;
        const RECURSIVE = 1 << 2;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindMountResult {
    Success,
    SourceNotFound,
    PermissionDenied,
    InvalidTarget,
}

/// Perform a bind mount
pub fn bind_mount<P: AsRef<Path>, Q: AsRef<Path>>(
    source: P,
    dest: Q,
    flags: BindMountFlags,
) -> Result<BindMountResult> {
    let source = source.as_ref();
    let dest = dest.as_ref();

    log::debug!(
        "bind_mount: source={}, dest={}, flags={:?}",
        source.display(),
        dest.display(),
        flags
    );

    // Check if source exists
    if !source.exists() {
        log::debug!("Bind mount source not found: {}", source.display());
        return Ok(BindMountResult::SourceNotFound);
    }

    // Determine mount flags
    let mut mount_flags = MsFlags::MS_BIND;

    if flags.contains(BindMountFlags::RECURSIVE) {
        mount_flags |= MsFlags::MS_REC;
        log::debug!("Using recursive bind mount");
    }

    // Perform the bind mount
    log::debug!(
        "Performing initial bind mount with flags: {:?}",
        mount_flags
    );
    mount(Some(source), dest, None::<&str>, mount_flags, None::<&str>).wrap_err_with(|| {
        format!(
            "Failed to bind mount {} to {}",
            source.display(),
            dest.display()
        )
    })?;
    log::debug!("Initial bind mount successful");

    // Apply readonly flag if requested
    if flags.contains(BindMountFlags::READONLY) {
        log::debug!("Remounting as read-only");
        let ro_flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY;

        mount(Some(source), dest, None::<&str>, ro_flags, None::<&str>)
            .wrap_err("Failed to remount as read-only")?;
        log::debug!("Successfully remounted as read-only");
    }

    // Apply device restrictions if needed
    if !flags.contains(BindMountFlags::DEVICES) {
        log::debug!("Applying nodev restriction");
        let nodev_flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_NODEV;

        mount(Some(source), dest, None::<&str>, nodev_flags, None::<&str>)
            .wrap_err("Failed to apply nodev flag")?;
        log::debug!("Successfully applied nodev restriction");
    }

    log::debug!("Bind mount completed successfully");
    Ok(BindMountResult::Success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bind_mount_flags() {
        let flags = BindMountFlags::READONLY | BindMountFlags::RECURSIVE;
        assert!(flags.contains(BindMountFlags::READONLY));
        assert!(flags.contains(BindMountFlags::RECURSIVE));
        assert!(!flags.contains(BindMountFlags::DEVICES));
    }
}
