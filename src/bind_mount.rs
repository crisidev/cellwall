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

    // Apply readonly and device flags if requested
    // Important: We need to apply both flags in a single remount operation
    // because separate remounts will override each other
    let needs_remount =
        flags.contains(BindMountFlags::READONLY) || !flags.contains(BindMountFlags::DEVICES);

    if needs_remount {
        let mut remount_flags = MsFlags::MS_BIND | MsFlags::MS_REMOUNT;

        if flags.contains(BindMountFlags::READONLY) {
            log::debug!("Applying readonly flag");
            remount_flags |= MsFlags::MS_RDONLY;
        }

        if !flags.contains(BindMountFlags::DEVICES) {
            log::debug!("Applying nodev restriction");
            remount_flags |= MsFlags::MS_NODEV;
        }

        log::debug!("Remounting with flags: {:?}", remount_flags);
        mount(
            None::<&str>,
            dest,
            None::<&str>,
            remount_flags,
            None::<&str>,
        )
        .wrap_err("Failed to apply remount flags")?;
        log::debug!("Successfully applied remount flags");
    }

    log::debug!("Bind mount completed successfully");
    Ok(BindMountResult::Success)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    #[test]
    fn test_bind_mount_source_not_found() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let source = PathBuf::from("/nonexistent/path/that/does/not/exist");
        let dest = temp_dir.path().join("dest");
        fs::create_dir(&dest)?;

        let result = bind_mount(&source, &dest, BindMountFlags::empty())?;
        assert_eq!(result, BindMountResult::SourceNotFound);

        Ok(())
    }

    #[test]
    fn test_bind_mount_flags_empty() {
        let flags = BindMountFlags::empty();
        assert!(!flags.contains(BindMountFlags::READONLY));
        assert!(!flags.contains(BindMountFlags::DEVICES));
        assert!(!flags.contains(BindMountFlags::RECURSIVE));
    }

    #[test]
    fn test_bind_mount_flags_readonly() {
        let flags = BindMountFlags::READONLY;
        assert!(flags.contains(BindMountFlags::READONLY));
        assert!(!flags.contains(BindMountFlags::DEVICES));
        assert!(!flags.contains(BindMountFlags::RECURSIVE));
    }

    #[test]
    fn test_bind_mount_flags_devices() {
        let flags = BindMountFlags::DEVICES;
        assert!(!flags.contains(BindMountFlags::READONLY));
        assert!(flags.contains(BindMountFlags::DEVICES));
        assert!(!flags.contains(BindMountFlags::RECURSIVE));
    }

    #[test]
    fn test_bind_mount_flags_recursive() {
        let flags = BindMountFlags::RECURSIVE;
        assert!(!flags.contains(BindMountFlags::READONLY));
        assert!(!flags.contains(BindMountFlags::DEVICES));
        assert!(flags.contains(BindMountFlags::RECURSIVE));
    }

    #[test]
    fn test_bind_mount_flags_combined() {
        let flags = BindMountFlags::READONLY | BindMountFlags::RECURSIVE;
        assert!(flags.contains(BindMountFlags::READONLY));
        assert!(!flags.contains(BindMountFlags::DEVICES));
        assert!(flags.contains(BindMountFlags::RECURSIVE));
    }

    #[test]
    fn test_bind_mount_flags_all() {
        let flags = BindMountFlags::READONLY | BindMountFlags::DEVICES | BindMountFlags::RECURSIVE;
        assert!(flags.contains(BindMountFlags::READONLY));
        assert!(flags.contains(BindMountFlags::DEVICES));
        assert!(flags.contains(BindMountFlags::RECURSIVE));
    }

    #[test]
    fn test_bind_mount_result_equality() {
        assert_eq!(BindMountResult::Success, BindMountResult::Success);
        assert_eq!(
            BindMountResult::SourceNotFound,
            BindMountResult::SourceNotFound
        );
        assert_eq!(
            BindMountResult::PermissionDenied,
            BindMountResult::PermissionDenied
        );
        assert_eq!(
            BindMountResult::InvalidTarget,
            BindMountResult::InvalidTarget
        );
    }

    #[test]
    fn test_bind_mount_result_inequality() {
        assert_ne!(BindMountResult::Success, BindMountResult::SourceNotFound);
        assert_ne!(BindMountResult::Success, BindMountResult::PermissionDenied);
        assert_ne!(
            BindMountResult::SourceNotFound,
            BindMountResult::InvalidTarget
        );
    }

    #[test]
    fn test_bind_mount_source_not_found_absolute_path() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let source = PathBuf::from("/this/path/absolutely/does/not/exist");
        let dest = temp_dir.path().join("dest");
        fs::create_dir(&dest)?;

        let result = bind_mount(&source, &dest, BindMountFlags::empty())?;
        assert_eq!(result, BindMountResult::SourceNotFound);

        Ok(())
    }

    #[test]
    fn test_bind_mount_source_not_found_with_flags() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let source = PathBuf::from("/nonexistent");
        let dest = temp_dir.path().join("dest");
        fs::create_dir(&dest)?;

        // Test with various flags - should still return SourceNotFound
        let flags = BindMountFlags::READONLY | BindMountFlags::RECURSIVE;
        let result = bind_mount(&source, &dest, flags)?;
        assert_eq!(result, BindMountResult::SourceNotFound);

        Ok(())
    }

    #[test]
    fn test_bind_mount_needs_privileges() {
        // Test that bind mounting requires privileges (unless we're root)
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&dest).unwrap();

        let result = bind_mount(&source, &dest, BindMountFlags::empty());

        // Will fail with EPERM unless running as root
        if nix::unistd::getuid().as_raw() != 0 {
            assert!(result.is_err());
            let err_msg = result.unwrap_err().to_string();
            assert!(
                err_msg.contains("Operation not permitted")
                    || err_msg.contains("Failed to bind mount")
            );
        }
    }

    #[test]
    fn test_bind_mount_readonly_needs_privileges() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&dest).unwrap();

        let result = bind_mount(&source, &dest, BindMountFlags::READONLY);

        if nix::unistd::getuid().as_raw() != 0 {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_bind_mount_recursive_needs_privileges() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&dest).unwrap();

        let result = bind_mount(&source, &dest, BindMountFlags::RECURSIVE);

        if nix::unistd::getuid().as_raw() != 0 {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_bind_mount_with_devices_needs_privileges() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("dest");
        fs::create_dir(&source).unwrap();
        fs::create_dir(&dest).unwrap();

        let result = bind_mount(&source, &dest, BindMountFlags::DEVICES);

        if nix::unistd::getuid().as_raw() != 0 {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_bind_mount_file_source_not_found() -> Result<()> {
        let tmp = TempDir::new()?;
        let source = PathBuf::from("/nonexistent/file.txt");
        let dest = tmp.path().join("file.txt");
        fs::File::create(&dest)?;

        let result = bind_mount(&source, &dest, BindMountFlags::empty())?;
        assert_eq!(result, BindMountResult::SourceNotFound);

        Ok(())
    }

    #[test]
    fn test_bind_mount_dest_nonexistent() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source");
        let dest = tmp.path().join("nonexistent_dest");
        fs::create_dir(&source).unwrap();
        // Don't create dest

        let result = bind_mount(&source, &dest, BindMountFlags::empty());

        if nix::unistd::getuid().as_raw() != 0 {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_bind_mount_source_is_file() {
        let tmp = TempDir::new().unwrap();
        let source = tmp.path().join("source.txt");
        let dest = tmp.path().join("dest.txt");
        fs::File::create(&source).unwrap();
        fs::File::create(&dest).unwrap();

        let result = bind_mount(&source, &dest, BindMountFlags::empty());

        if nix::unistd::getuid().as_raw() != 0 {
            assert!(result.is_err());
        }
    }

    #[test]
    fn test_bind_mount_flags_debug_format() {
        // Test that debug formatting works (we added #[derive(Debug)])
        let flags = BindMountFlags::READONLY | BindMountFlags::RECURSIVE;
        let debug_str = format!("{:?}", flags);
        assert!(!debug_str.is_empty());
    }

    #[test]
    fn test_bind_mount_result_debug_format() {
        let result = BindMountResult::Success;
        let debug_str = format!("{:?}", result);
        assert!(debug_str.contains("Success"));
    }

    #[test]
    fn test_bind_mount_result_clone() {
        let result = BindMountResult::SourceNotFound;
        let cloned = result;
        assert_eq!(result, cloned);
    }
}
