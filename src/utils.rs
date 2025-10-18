//! Utility functions

use eyre::{bail, Result};
use nix::fcntl::{openat, OFlag};
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
    if let Some(parent) = path.as_ref().parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
            fs::set_permissions(parent, Permissions::from_mode(mode))?;
        }
    }
    Ok(())
}

/// Close all file descriptors except the ones in the excluded list
pub fn close_extra_fds(excluded: &[RawFd]) -> Result<()> {
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        if let Ok(fd_str) = entry.file_name().into_string() {
            if let Ok(fd) = fd_str.parse::<RawFd>() {
                if !excluded.contains(&fd) && fd > 2 {
                    close(fd).ok();
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_ensure_dir() -> Result<()> {
        let tmp = TempDir::new()?;
        let dir_path = tmp.path().join("test_dir");

        ensure_dir(&dir_path, 0o755)?;
        assert!(dir_path.is_dir());

        // Should not error if dir already exists
        ensure_dir(&dir_path, 0o755)?;

        Ok(())
    }
}
