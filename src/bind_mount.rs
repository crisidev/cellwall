//! Bind mount operations

use eyre::{Context, Result};
use nix::mount::{MsFlags, mount};
use std::fs;
use std::path::{Path, PathBuf};

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
pub(crate) enum BindMountResult {
    Success,
    SourceNotFound,
}

/// Unescape octal sequences in mount paths
/// Based on bubblewrap's unescape_inline function.
/// Mountinfo encodes spaces and other special characters as octal escapes like \040
fn unescape_path(escaped: &str) -> String {
    let mut result = String::with_capacity(escaped.len());
    let mut chars = escaped.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch != '\\' {
            result.push(ch);
            continue;
        }

        // Manually collect up to 3 octal digits using peek to avoid consuming non-octal chars
        let mut octal_chars = String::new();
        for _ in 0..3 {
            if let Some(&c) = chars.peek() {
                if c.is_ascii_digit() && c <= '7' {
                    octal_chars.push(c);
                    chars.next(); // consume the char we just peeked
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        // Only process if we got exactly 3 octal digits
        if octal_chars.len() == 3 {
            match u8::from_str_radix(&octal_chars, 8) {
                Ok(byte_val) if byte_val.is_ascii() => {
                    // Safe to convert ASCII byte to char
                    result.push(byte_val as char);
                }
                _ => {
                    // Invalid octal value or non-ASCII, keep original
                    result.push('\\');
                    result.push_str(&octal_chars);
                }
            }
        } else {
            // Not enough digits for valid octal escape, keep as-is
            result.push('\\');
            result.push_str(&octal_chars);
        }
    }

    result
}

/// Parse mount options from a comma-separated string into MsFlags
/// Based on bubblewrap's decode_mountoptions function
fn parse_mount_options(options: &str) -> MsFlags {
    let mut flags = MsFlags::empty();

    for opt in options.split(',') {
        match opt {
            "ro" => flags |= MsFlags::MS_RDONLY,
            "nosuid" => flags |= MsFlags::MS_NOSUID,
            "nodev" => flags |= MsFlags::MS_NODEV,
            "noexec" => flags |= MsFlags::MS_NOEXEC,
            "noatime" => flags |= MsFlags::MS_NOATIME,
            "nodiratime" => flags |= MsFlags::MS_NODIRATIME,
            "relatime" => flags |= MsFlags::MS_RELATIME,
            // "rw" and other options don't have flags
            _ => {}
        }
    }

    flags
}

/// Get the current mount flags for a given mount point from /proc/self/mountinfo
/// Returns None if the mount point is not found
fn get_mount_flags(mount_point: &Path) -> Result<Option<MsFlags>> {
    log::debug!("Looking up mount flags for {}", mount_point.display());

    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .context("Failed to read /proc/self/mountinfo")?;

    // Canonicalize the mount point to match what's in mountinfo
    let canonical = mount_point
        .canonicalize()
        .context("Failed to canonicalize mount point")?;

    for line in mountinfo.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        // Format: mount_id parent_id major:minor root mount_point options ...
        // mount_point is at index 4, options at index 5
        let mount_path = PathBuf::from(unescape_path(parts[4]));

        // Check if this is the mount we're looking for
        if mount_path == canonical {
            let options = parts[5];
            let flags = parse_mount_options(options);
            log::debug!(
                "Found mount flags for {}: {:?} (from options: {})",
                mount_point.display(),
                flags,
                options
            );
            return Ok(Some(flags));
        }
    }

    log::debug!(
        "No mount flags found for {} in /proc/self/mountinfo",
        mount_point.display()
    );
    Ok(None)
}

/// Mount info line parsed from /proc/self/mountinfo
#[derive(Debug, Clone)]
struct MountInfoLine {
    id: i32,
    parent_id: i32,
    mountpoint: PathBuf,
    options: MsFlags,
}

/// Parse /proc/self/mountinfo to find all submounts under a given path
/// Returns a list of (mount_point, options) tuples for children of the root_mount path
/// This matches bubblewrap's parse_mountinfo function behavior by building a parent-child tree
fn parse_submounts(root_mount: &Path) -> Result<Vec<(PathBuf, MsFlags)>> {
    log::debug!(
        "Parsing /proc/self/mountinfo for submounts under {}",
        root_mount.display()
    );

    let mountinfo = fs::read_to_string("/proc/self/mountinfo")
        .context("Failed to read /proc/self/mountinfo")?;

    // Parse all mount info lines
    let mut lines = Vec::new();
    let mut root_idx: Option<usize> = None;

    for line in mountinfo.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 6 {
            continue;
        }

        // Format: mount_id parent_id major:minor root mount_point options ...
        let mount_id = parts[0]
            .parse::<i32>()
            .context("Failed to parse mount_id")?;
        let parent_id = parts[1]
            .parse::<i32>()
            .context("Failed to parse parent_id")?;
        let mount_point = PathBuf::from(unescape_path(parts[4]));
        let options = parse_mount_options(parts[5]);

        // Find the root mount (the one we just created)
        if mount_point == root_mount {
            root_idx = Some(lines.len());
        }

        lines.push(MountInfoLine {
            id: mount_id,
            parent_id,
            mountpoint: mount_point,
            options,
        });
    }

    // If we didn't find the root mount, return empty
    let root_idx = match root_idx {
        Some(idx) => idx,
        None => {
            log::debug!("Root mount {} not found in mountinfo", root_mount.display());
            return Ok(Vec::new());
        }
    };

    let root_id = lines[root_idx].id;
    log::debug!(
        "Found root mount at index {} with mount_id {}",
        root_idx,
        root_id
    );

    // Build a map of mount_id -> line for quick lookup
    let by_id: std::collections::HashMap<i32, &MountInfoLine> =
        lines.iter().map(|line| (line.id, line)).collect();

    // Collect all mounts that are descendants of the root mount
    // A mount is a descendant if following parent_id links eventually leads to root_id
    let mut submounts = Vec::new();

    for line in &lines {
        // Skip the root mount itself
        if line.id == root_id {
            continue;
        }

        // Skip mounts created after our root mount
        // This is critical for supporting writable bind mounts under readonly parents.
        // When a mount is created after our root mount, it should not be remounted
        // because it was set up independently with its own flags.
        // Mount IDs are assigned sequentially by the kernel, so if mount_id > root_id,
        // it means this mount was created after our mount operation.
        if line.id > root_id {
            log::debug!(
                "Skipping mount {} (mount_id={} > root_id={}, created after root mount)",
                line.mountpoint.display(),
                line.id,
                root_id
            );
            continue;
        }

        // Check if this mount point is under our root_mount path
        if !line.mountpoint.starts_with(root_mount) {
            continue;
        }

        // Check if this mount is a descendant of root by following parent links
        let mut current_id = line.parent_id;
        let mut is_descendant = false;

        // Walk up the parent chain
        while let Some(parent) = by_id.get(&current_id) {
            if parent.id == root_id {
                is_descendant = true;
                break;
            }
            current_id = parent.parent_id;

            // Prevent infinite loops (shouldn't happen in valid mountinfo)
            if current_id == parent.id {
                break;
            }
        }

        if is_descendant {
            log::debug!(
                "Found submount: {} (mount_id={}, parent_id={}) with flags: {:?}",
                line.mountpoint.display(),
                line.id,
                line.parent_id,
                line.options
            );
            submounts.push((line.mountpoint.clone(), line.options));
        } else {
            log::debug!(
                "Skipping mount {} (not a descendant of root mount_id={})",
                line.mountpoint.display(),
                root_id
            );
        }
    }

    log::debug!(
        "Found {} submounts that are descendants of root",
        submounts.len()
    );
    Ok(submounts)
}

/// Perform a bind mount
pub(crate) fn bind_mount<P: AsRef<Path>, Q: AsRef<Path>>(
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
    // Add MS_SILENT to suppress kernel warnings (matches bubblewrap)
    mount_flags |= MsFlags::MS_SILENT;
    mount(Some(source), dest, None::<&str>, mount_flags, None::<&str>).wrap_err_with(|| {
        format!(
            "Failed to bind mount {} to {}",
            source.display(),
            dest.display()
        )
    })?;
    log::debug!("Initial bind mount successful");

    // Apply security flags via remount
    // Important: We need to apply all flags in a single remount operation
    // because separate remounts will override each other
    //
    // We preserve existing mount flags and OR them with our security flags
    // This matches bubblewrap's behavior (see bind-mount.c lines 448-450)
    //
    // Security flags applied:
    // - MS_NOSUID: Always applied to prevent setuid escalation (matches bubblewrap)
    // - MS_RDONLY: Applied if READONLY flag is set
    // - MS_NODEV: Applied unless DEVICES flag is set

    // Get existing mount flags from /proc/self/mountinfo
    let existing_flags = match get_mount_flags(dest) {
        Ok(Some(flags)) => {
            log::debug!("Preserving existing mount flags: {:?}", flags);
            flags
        }
        Ok(None) => {
            log::debug!("No existing mount flags found, starting fresh");
            MsFlags::empty()
        }
        Err(e) => {
            log::warn!("Failed to get existing mount flags: {}, starting fresh", e);
            MsFlags::empty()
        }
    };

    // Build new flags by OR'ing existing flags with our security requirements
    let mut remount_flags =
        MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_SILENT | existing_flags;

    // Always add MS_NOSUID for security (prevents setuid escalation)
    log::debug!("Applying nosuid restriction (always for security)");
    remount_flags |= MsFlags::MS_NOSUID;

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

    // Apply flags to all submounts when using recursive bind mounts
    // This is necessary because bind mounts don't automatically apply flags to submounts
    // See bubblewrap bind-mount.c lines 461-486
    //
    // The key insight from bubblewrap:
    // 1. Use realpath() on the destination AFTER the mount to resolve symlinks
    // 2. Open the destination with O_PATH and readlink /proc/self/fd/<fd>
    // 3. Parse mountinfo using the kernel's path representation
    // 4. Remount submounts using the exact paths from mountinfo
    if flags.contains(BindMountFlags::RECURSIVE) {
        log::debug!("Applying flags to submounts (recursive bind mount)");

        // Resolve the destination path after the mount operation
        // This matches bubblewrap's realpath(dest) call at line 404
        let resolved_dest = dest
            .canonicalize()
            .wrap_err_with(|| format!("Failed to resolve destination: {}", dest.display()))?;

        log::debug!(
            "Resolved destination: {} -> {}",
            dest.display(),
            resolved_dest.display()
        );

        // Open the destination with O_PATH to get a file descriptor
        // Then read /proc/self/fd/<fd> to get the kernel's path representation
        // This handles case-insensitive filesystems correctly (bubblewrap lines 408-436)
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        let dest_file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC)
            .open(&resolved_dest)
            .wrap_err_with(|| {
                format!(
                    "Failed to open destination with O_PATH: {}",
                    resolved_dest.display()
                )
            })?;

        let dest_fd = dest_file.as_raw_fd();
        let fd_path = format!("/proc/self/fd/{}", dest_fd);

        // Read the symlink to get the kernel's representation of the path
        let kernel_path = std::fs::read_link(&fd_path)
            .wrap_err_with(|| format!("Failed to readlink {}", fd_path))?;

        log::debug!(
            "Kernel path representation: {} (from {})",
            kernel_path.display(),
            fd_path
        );

        // Parse submounts under the kernel's path representation
        // This gives us the exact paths as they appear in /proc/self/mountinfo
        match parse_submounts(&kernel_path) {
            Ok(submounts) => {
                for (submount_path, existing_flags) in submounts {
                    log::debug!(
                        "Remounting submount: {} (existing flags: {:?})",
                        submount_path.display(),
                        existing_flags
                    );

                    // Check if the submount path actually exists in the current namespace
                    // If it doesn't exist, it's likely from a different mount namespace
                    if !submount_path.exists() {
                        log::debug!(
                            "Skipping submount {} (doesn't exist in current namespace)",
                            submount_path.display()
                        );
                        continue;
                    }

                    // Build new flags by OR'ing existing flags with security requirements
                    // This matches bubblewrap's logic at lines 469-470
                    let mut new_flags = MsFlags::MS_BIND
                        | MsFlags::MS_REMOUNT
                        | MsFlags::MS_SILENT
                        | existing_flags;
                    new_flags |= MsFlags::MS_NOSUID;

                    if flags.contains(BindMountFlags::READONLY) {
                        new_flags |= MsFlags::MS_RDONLY;
                    }

                    if !flags.contains(BindMountFlags::DEVICES) {
                        new_flags |= MsFlags::MS_NODEV;
                    }

                    // Only remount if flags have changed
                    if new_flags != existing_flags {
                        // Try to remount with the new flags
                        // Use the exact path from mountinfo (bubblewrap line 472)
                        match mount(
                            None::<&str>,
                            &submount_path,
                            None::<&str>,
                            new_flags,
                            None::<&str>,
                        ) {
                            Ok(_) => {
                                log::debug!(
                                    "Successfully remounted submount: {}",
                                    submount_path.display()
                                );
                            }
                            Err(nix::errno::Errno::EACCES) => {
                                // If we can't read the mountpoint, we can't remount it,
                                // but that's safe to ignore because the user can't access it anyway.
                                // This matches bubblewrap's behavior at lines 475-477
                                log::debug!(
                                    "Ignoring EACCES for submount {} (user can't access it anyway)",
                                    submount_path.display()
                                );
                            }
                            Err(e) => {
                                // For other errors (including EINVAL, ENOENT), this is a real problem
                                // Now that we properly filter mounts by parent-child relationships,
                                // we should only be trying to remount mounts that are actually part
                                // of our recursive bind mount tree.
                                // Bubblewrap would return an error here (line 254), but we'll log a
                                // warning and continue to be more resilient.
                                log::warn!(
                                    "Failed to remount submount {}: {}",
                                    submount_path.display(),
                                    e
                                );
                            }
                        }
                    } else {
                        log::debug!(
                            "Submount {} already has correct flags, skipping remount",
                            submount_path.display()
                        );
                    }
                }
            }
            Err(e) => {
                // If we can't parse mountinfo, log a warning but don't fail the whole operation
                log::warn!("Failed to parse submounts: {}", e);
            }
        }
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
    fn test_unescape_path_no_escapes() {
        assert_eq!(unescape_path("/simple/path"), "/simple/path");
        assert_eq!(unescape_path("/var/log"), "/var/log");
        assert_eq!(unescape_path(""), "");
    }

    #[test]
    fn test_unescape_path_space() {
        // \040 is octal for space (ASCII 32)
        assert_eq!(
            unescape_path("/path\\040with\\040spaces"),
            "/path with spaces"
        );
        assert_eq!(unescape_path("\\040"), " ");
        assert_eq!(unescape_path("before\\040after"), "before after");
    }

    #[test]
    fn test_unescape_path_tab() {
        // \011 is octal for tab (ASCII 9)
        assert_eq!(
            unescape_path("/path\\011with\\011tabs"),
            "/path\twith\ttabs"
        );
    }

    #[test]
    fn test_unescape_path_newline() {
        // \012 is octal for newline (ASCII 10)
        assert_eq!(
            unescape_path("/path\\012with\\012newlines"),
            "/path\nwith\nnewlines"
        );
    }

    #[test]
    fn test_unescape_path_multiple_escapes() {
        // Mix of different escaped characters
        assert_eq!(
            unescape_path("/path\\040with\\011mixed\\012escapes"),
            "/path with\tmixed\nescapes"
        );
    }

    #[test]
    fn test_unescape_path_invalid_escape_too_few_digits() {
        // Backslash followed by fewer than 3 octal digits
        assert_eq!(unescape_path("/path\\04"), "/path\\04");
        assert_eq!(unescape_path("/path\\0"), "/path\\0");
        assert_eq!(unescape_path("/path\\"), "/path\\");
    }

    #[test]
    fn test_unescape_path_invalid_escape_non_octal() {
        // Backslash followed by non-octal characters
        // Since 'n' and 't' aren't octal digits (0-7), take_while stops immediately
        assert_eq!(unescape_path("/path\\n"), "/path\\n");
        assert_eq!(unescape_path("/path\\t"), "/path\\t");
        // '9' is not an octal digit, so it stops immediately and we get backslash + "99" + "9"
        assert_eq!(unescape_path("/path\\999"), "/path\\999");
    }

    #[test]
    fn test_unescape_path_invalid_octal_value() {
        // '8' and '9' are not octal digits (0-7), so take_while stops immediately
        assert_eq!(unescape_path("/path\\888"), "/path\\888");
        assert_eq!(unescape_path("/path\\999"), "/path\\999");
    }

    #[test]
    fn test_unescape_path_out_of_range() {
        // Octal value > 127 (non-ASCII)
        // \200 = 128 in decimal (first non-ASCII value)
        assert_eq!(unescape_path("/path\\200test"), "/path\\200test");
        assert_eq!(unescape_path("/path\\377test"), "/path\\377test");
    }

    #[test]
    fn test_unescape_path_consecutive_escapes() {
        // Multiple escapes in a row
        assert_eq!(unescape_path("\\040\\040\\040"), "   ");
        assert_eq!(unescape_path("a\\040\\040b"), "a  b");
    }

    #[test]
    fn test_unescape_path_escape_at_end() {
        assert_eq!(unescape_path("/path\\040"), "/path ");
        assert_eq!(unescape_path("/path\\04"), "/path\\04");
    }

    #[test]
    fn test_unescape_path_real_world_examples() {
        // Real examples from mountinfo
        assert_eq!(
            unescape_path("/var/lib/docker/overlay2/abc\\040def"),
            "/var/lib/docker/overlay2/abc def"
        );
        assert_eq!(unescape_path("/mnt/My\\040Documents"), "/mnt/My Documents");
    }

    #[test]
    fn test_unescape_path_null_byte() {
        // \000 is octal for null byte (ASCII 0)
        assert_eq!(unescape_path("before\\000after"), "before\0after");
    }

    #[test]
    fn test_unescape_path_all_ascii_control_chars() {
        // Test various ASCII control characters
        assert_eq!(unescape_path("\\001"), "\x01"); // SOH
        assert_eq!(unescape_path("\\033"), "\x1b"); // ESC
        assert_eq!(unescape_path("\\177"), "\x7f"); // DEL
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

        assert!(result.is_err());
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
}
