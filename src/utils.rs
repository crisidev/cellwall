//! Utility functions

use eyre::{Result, bail};
use std::fs::{self, File, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

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
}
