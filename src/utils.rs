//! Utility functions

use eyre::{Result, bail};
use nix::fcntl::{OFlag, openat};
use nix::sys::stat::Mode;
use nix::unistd::{close, read};
use std::fs::{self, File, Permissions};
use std::os::fd::{AsFd, BorrowedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::RawFd;
use std::path::Path;

/// Read all data from a file descriptor into a Vec
pub fn read_fd_to_vec<Fd: AsFd>(fd: Fd) -> Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];

    loop {
        match read(&fd, &mut chunk) {
            Ok(0) => break,
            Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(buffer)
}

/// Read file contents as string from a directory fd
pub fn read_file_at(dirfd: RawFd, path: &str) -> Result<String> {
    if dirfd < 0 {
        // If no dirfd provided, use normal file operations
        return Ok(fs::read_to_string(path)?);
    }

    // Create a BorrowedFd from the raw fd
    let borrowed_dirfd = unsafe { BorrowedFd::borrow_raw(dirfd) };

    let fd = openat(
        borrowed_dirfd,
        path,
        OFlag::O_RDONLY | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;

    let contents = read_fd_to_vec(&fd)?;
    close(fd)?;

    Ok(String::from_utf8(contents)?)
}

/// Write string to a file relative to a directory fd
pub fn write_file_at(dirfd: RawFd, path: &str, contents: &str) -> Result<()> {
    if dirfd < 0 {
        // If no dirfd provided, use normal file operations
        return Ok(fs::write(path, contents)?);
    }

    // Create a BorrowedFd from the raw dirfd
    let borrowed_dirfd = unsafe { BorrowedFd::borrow_raw(dirfd) };

    let fd = openat(
        borrowed_dirfd,
        path,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_TRUNC | OFlag::O_CLOEXEC,
        Mode::S_IRUSR | Mode::S_IWUSR | Mode::S_IRGRP | Mode::S_IROTH,
    )?;

    nix::unistd::write(&fd, contents.as_bytes())?;
    close(fd)?;

    Ok(())
}

/// Check if path is a directory
pub fn is_dir<P: AsRef<Path>>(path: P) -> Result<bool> {
    Ok(fs::metadata(path.as_ref())?.is_dir())
}

/// Ensure a directory exists with given permissions
pub fn ensure_dir<P: AsRef<Path>>(path: P, mode: u32) -> Result<()> {
    let path = path.as_ref();

    if path.exists() {
        if !path.is_dir() {
            bail!("{} exists but is not a directory", path.display());
        }
        return Ok(());
    }

    fs::create_dir(path)?;
    fs::set_permissions(path, Permissions::from_mode(mode))?;

    Ok(())
}

/// Ensure a file exists with given permissions
pub fn ensure_file<P: AsRef<Path>>(path: P, mode: u32) -> Result<()> {
    let path = path.as_ref();

    if !path.exists() {
        File::create(path)?;
        fs::set_permissions(path, Permissions::from_mode(mode))?;
    }

    Ok(())
}

/// Create parent directories with given permissions
pub fn create_parent_dirs<P: AsRef<Path>>(path: P, mode: u32) -> Result<()> {
    if let Some(parent) = path.as_ref().parent()
        && !parent.exists()
    {
        fs::create_dir_all(parent)?;
        fs::set_permissions(parent, Permissions::from_mode(mode))?;
    }
    Ok(())
}

/// Close all file descriptors except the ones in the excluded list
pub fn close_extra_fds(excluded: &[RawFd]) -> Result<()> {
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        if let Ok(fd_str) = entry.file_name().into_string()
            && let Ok(fd) = fd_str.parse::<RawFd>()
            && !excluded.contains(&fd)
            && fd > 2
        {
            close(fd).ok();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    #[test]
    fn test_ensure_dir_creates_directory() -> Result<()> {
        let tmp = TempDir::new()?;
        let dir_path = tmp.path().join("test_dir");

        assert!(!dir_path.exists());
        ensure_dir(&dir_path, 0o755)?;
        assert!(dir_path.is_dir());

        let metadata = fs::metadata(&dir_path)?;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o755);

        Ok(())
    }

    #[test]
    fn test_ensure_dir_idempotent() -> Result<()> {
        let tmp = TempDir::new()?;
        let dir_path = tmp.path().join("test_dir");

        ensure_dir(&dir_path, 0o755)?;
        ensure_dir(&dir_path, 0o755)?; // Should not error

        assert!(dir_path.is_dir());

        Ok(())
    }

    #[test]
    fn test_ensure_dir_fails_if_file_exists() -> Result<()> {
        let tmp = TempDir::new()?;
        let file_path = tmp.path().join("test_file");
        File::create(&file_path)?;

        let result = ensure_dir(&file_path, 0o755);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a directory"));

        Ok(())
    }

    #[test]
    fn test_ensure_file_creates_file() -> Result<()> {
        let tmp = TempDir::new()?;
        let file_path = tmp.path().join("test_file");

        assert!(!file_path.exists());
        ensure_file(&file_path, 0o644)?;
        assert!(file_path.is_file());

        let metadata = fs::metadata(&file_path)?;
        assert_eq!(metadata.permissions().mode() & 0o777, 0o644);

        Ok(())
    }

    #[test]
    fn test_ensure_file_idempotent() -> Result<()> {
        let tmp = TempDir::new()?;
        let file_path = tmp.path().join("test_file");

        ensure_file(&file_path, 0o644)?;
        ensure_file(&file_path, 0o644)?; // Should not error

        assert!(file_path.is_file());

        Ok(())
    }

    #[test]
    fn test_create_parent_dirs() -> Result<()> {
        let tmp = TempDir::new()?;
        let nested_path = tmp.path().join("a").join("b").join("c").join("file");

        create_parent_dirs(&nested_path, 0o755)?;

        assert!(tmp.path().join("a").is_dir());
        assert!(tmp.path().join("a").join("b").is_dir());
        assert!(tmp.path().join("a").join("b").join("c").is_dir());
        assert!(!nested_path.exists());

        Ok(())
    }

    #[test]
    fn test_create_parent_dirs_no_op_if_exists() -> Result<()> {
        let tmp = TempDir::new()?;
        let dir_path = tmp.path().join("existing");
        fs::create_dir(&dir_path)?;

        let file_path = dir_path.join("file");
        create_parent_dirs(&file_path, 0o755)?;

        assert!(dir_path.is_dir());

        Ok(())
    }

    #[test]
    fn test_is_dir_true() -> Result<()> {
        let tmp = TempDir::new()?;
        assert!(is_dir(tmp.path())?);
        Ok(())
    }

    #[test]
    fn test_is_dir_false() -> Result<()> {
        let tmp = TempDir::new()?;
        let file_path = tmp.path().join("file");
        File::create(&file_path)?;

        assert!(!is_dir(&file_path)?);

        Ok(())
    }

    #[test]
    fn test_is_dir_nonexistent() {
        let result = is_dir("/nonexistent/path");
        assert!(result.is_err());
    }
}
