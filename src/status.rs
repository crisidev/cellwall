//! Status reporting for sandbox information
//!
//! This module implements status reporting similar to bubblewrap's --info-fd
//! and --json-status-fd functionality. It reports namespace IDs and child PIDs.

use eyre::Result;
use std::fs;
use std::os::unix::io::RawFd;

/// Namespace information
#[derive(Debug, Clone)]
pub struct NamespaceInfo {
    pub name: String,
    pub id: u64,
}

/// Get namespace IDs for a given PID
/// Based on bubblewrap's namespace_ids_read function (bubblewrap.c lines 2812-2842)
pub fn read_namespace_ids(pid: i32) -> Result<Vec<NamespaceInfo>> {
    let ns_path = format!("/proc/{}/ns", pid);
    let mut namespaces = Vec::new();

    // List of namespace types we care about
    // From bubblewrap's ns_infos (bubblewrap.c lines 110-121)
    let namespace_types = ["cgroup", "ipc", "mnt", "net", "pid", "uts"];

    for ns_type in &namespace_types {
        let ns_file = format!("{}/{}", ns_path, ns_type);

        // Try to stat the namespace file to get its inode number
        // The inode number is the namespace ID
        if let Ok(metadata) = fs::metadata(&ns_file) {
            use std::os::unix::fs::MetadataExt;
            let ns_id = metadata.ino();

            if ns_id != 0 {
                namespaces.push(NamespaceInfo {
                    name: ns_type.to_string(),
                    id: ns_id,
                });
            }
        }
    }

    Ok(namespaces)
}

/// Write namespace information in human-readable format
/// Based on bubblewrap's namespace_ids_write with in_json=false (lines 2845-2868)
fn format_namespaces_text(namespaces: &[NamespaceInfo]) -> String {
    let mut output = String::new();

    for ns in namespaces {
        output.push_str(&format!("\n    \"{}-namespace\": {}", ns.name, ns.id));
    }

    output
}

/// Write namespace information in JSON format
/// Based on bubblewrap's namespace_ids_write with in_json=true (lines 2845-2868)
fn format_namespaces_json(namespaces: &[NamespaceInfo]) -> String {
    let mut output = String::new();

    for ns in namespaces {
        output.push_str(&format!(", \"{}-namespace\": {}", ns.name, ns.id));
    }

    output
}

/// Write info to file descriptor
/// Based on bubblewrap's dump_info function (lines 457-465)
pub fn write_to_fd(fd: RawFd, data: &str) -> Result<()> {
    let bytes = data.as_bytes();
    let mut written = 0;

    while written < bytes.len() {
        // Use libc::write directly to avoid AsFd trait requirements
        let n = unsafe {
            libc::write(
                fd,
                bytes[written..].as_ptr() as *const libc::c_void,
                bytes.len() - written,
            )
        };

        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(err.into());
        }

        written += n as usize;
    }

    Ok(())
}

/// Report sandbox information in human-readable format
/// Based on bubblewrap's info_fd reporting (lines 3183-3190)
pub fn report_info(fd: RawFd, child_pid: i32, namespaces: &[NamespaceInfo]) -> Result<()> {
    let mut output = format!("{{\n    \"child-pid\": {}", child_pid);
    output.push_str(&format_namespaces_text(namespaces));
    output.push_str("\n}\n");

    write_to_fd(fd, &output)?;
    Ok(())
}

/// Report sandbox status in JSON format
/// Based on bubblewrap's json_status_fd reporting (lines 3191-3197)
pub fn report_json_status(fd: RawFd, child_pid: i32, namespaces: &[NamespaceInfo]) -> Result<()> {
    let mut output = format!("{{ \"child-pid\": {}", child_pid);
    output.push_str(&format_namespaces_json(namespaces));
    output.push_str(" }}\n");

    write_to_fd(fd, &output)?;
    Ok(())
}

/// Report child exit status in JSON format
/// Based on bubblewrap's report_child_exit_status function (lines 468-487)
pub fn report_exit_status(fd: RawFd, exit_code: i32) -> Result<()> {
    let output = format!("{{ \"exit-code\": {} }}\n", exit_code);
    write_to_fd(fd, &output)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_namespaces_text() {
        let namespaces = vec![
            NamespaceInfo {
                name: "mnt".to_string(),
                id: 4026531841,
            },
            NamespaceInfo {
                name: "net".to_string(),
                id: 4026531993,
            },
        ];

        let output = format_namespaces_text(&namespaces);
        assert!(output.contains("\"mnt-namespace\": 4026531841"));
        assert!(output.contains("\"net-namespace\": 4026531993"));
    }

    #[test]
    fn test_format_namespaces_json() {
        let namespaces = vec![NamespaceInfo {
            name: "pid".to_string(),
            id: 4026531836,
        }];

        let output = format_namespaces_json(&namespaces);
        assert_eq!(output, ", \"pid-namespace\": 4026531836");
    }

    #[test]
    fn test_read_namespace_ids_self() {
        // Test reading our own namespace IDs
        let namespaces = read_namespace_ids(std::process::id() as i32);

        // Should succeed for our own process
        assert!(namespaces.is_ok());

        let namespaces = namespaces.unwrap();

        // Should have at least mnt, pid, net namespaces
        assert!(!namespaces.is_empty());

        // Check that we have some expected namespaces
        let ns_names: Vec<_> = namespaces.iter().map(|n| n.name.as_str()).collect();
        assert!(ns_names.contains(&"mnt"));
    }

    #[test]
    fn test_read_namespace_ids_nonexistent() {
        // Test with a PID that doesn't exist
        let result = read_namespace_ids(999999);

        // Should return Ok but with empty namespaces (or error is also fine)
        // We don't fail hard on this
        assert!(result.is_ok());
    }
}
