//! Namespace management

use eyre::{Context, Result};
use nix::sched::{CloneFlags, unshare};
use nix::unistd::{Gid, Pid, Uid};
use std::fs;
use std::os::unix::io::RawFd;

/// Unshare namespaces based on flags
pub(crate) fn unshare_namespaces(flags: CloneFlags) -> Result<()> {
    log::debug!("Calling unshare() with flags: {:?}", flags);
    unshare(flags).wrap_err("Failed to unshare namespaces")?;
    log::debug!("unshare() syscall succeeded");
    Ok(())
}

/// Write UID/GID mappings for user namespace
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_uid_gid_map(
    _proc_fd: RawFd,
    sandbox_uid: Uid,
    parent_uid: Uid,
    sandbox_gid: Gid,
    parent_gid: Gid,
    pid: Option<Pid>,
    deny_groups: bool,
    map_root: bool,
    overflow_uid: Uid,
    overflow_gid: Gid,
) -> Result<()> {
    let pid_str = pid
        .map(|p| p.to_string())
        .unwrap_or_else(|| "self".to_string());

    log::debug!("Writing UID/GID mappings for process {}", pid_str);
    log::debug!(
        "Map configuration: deny_groups={}, map_root={}",
        deny_groups,
        map_root
    );

    // Build UID map
    let uid_map = if map_root && parent_uid.as_raw() != 0 && sandbox_uid.as_raw() != 0 {
        format!(
            "0 {} 1\n{} {} 1\n",
            overflow_uid.as_raw(),
            sandbox_uid.as_raw(),
            parent_uid.as_raw()
        )
    } else {
        format!("{} {} 1\n", sandbox_uid.as_raw(), parent_uid.as_raw())
    };
    log::debug!("UID map:\n{}", uid_map.trim());

    // Build GID map
    let gid_map = if map_root && parent_gid.as_raw() != 0 && sandbox_gid.as_raw() != 0 {
        format!(
            "0 {} 1\n{} {} 1\n",
            overflow_gid.as_raw(),
            sandbox_gid.as_raw(),
            parent_gid.as_raw()
        )
    } else {
        format!("{} {} 1\n", sandbox_gid.as_raw(), parent_gid.as_raw())
    };
    log::debug!("GID map:\n{}", gid_map.trim());

    // Write uid_map
    let uid_map_path = format!("/proc/{}/uid_map", pid_str);
    log::debug!("Writing uid_map to {}", uid_map_path);
    fs::write(&uid_map_path, &uid_map)
        .wrap_err_with(|| format!("Failed to write uid_map to {}", uid_map_path))?;
    log::debug!("Successfully wrote uid_map");

    // Write setgroups if needed
    if deny_groups {
        let setgroups_path = format!("/proc/{}/setgroups", pid_str);
        log::debug!("Writing 'deny' to {}", setgroups_path);
        // Ignore error if setgroups doesn't exist (older kernels)
        if let Err(e) = fs::write(&setgroups_path, "deny\n") {
            log::debug!("Could not write setgroups (may not be supported): {}", e);
        } else {
            log::debug!("Successfully wrote setgroups");
        }
    }

    // Write gid_map
    let gid_map_path = format!("/proc/{}/gid_map", pid_str);
    log::debug!("Writing gid_map to {}", gid_map_path);
    fs::write(&gid_map_path, &gid_map)
        .wrap_err_with(|| format!("Failed to write gid_map to {}", gid_map_path))?;
    log::debug!("Successfully wrote gid_map");

    Ok(())
}
