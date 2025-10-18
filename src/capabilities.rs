//! Capability management

use eyre::{Context, Result};
use nix::unistd::{Gid, Uid, setgid, setuid};

/// Drop all capabilities
pub fn drop_all_caps() -> Result<()> {
    log::debug!("Dropping all capabilities");
    caps::clear(None, caps::CapSet::Permitted)
        .wrap_err("Failed to clear permitted capabilities")?;
    caps::clear(None, caps::CapSet::Effective)
        .wrap_err("Failed to clear effective capabilities")?;
    caps::clear(None, caps::CapSet::Inheritable)
        .wrap_err("Failed to clear inheritable capabilities")?;
    log::debug!("All capabilities cleared");

    Ok(())
}

/// Set required capabilities for setup
pub fn set_required_caps() -> Result<()> {
    use caps::Capability;
    use std::collections::HashSet;

    let required_caps: HashSet<_> = vec![
        Capability::CAP_SYS_ADMIN,
        Capability::CAP_SYS_CHROOT,
        Capability::CAP_NET_ADMIN,
        Capability::CAP_SETUID,
        Capability::CAP_SETGID,
        Capability::CAP_SYS_PTRACE,
    ]
    .into_iter()
    .collect();

    caps::set(None, caps::CapSet::Effective, &required_caps)
        .wrap_err("Failed to set effective capabilities")?;
    caps::set(None, caps::CapSet::Permitted, &required_caps)
        .wrap_err("Failed to set permitted capabilities")?;

    Ok(())
}

/// Check if we have any capabilities
pub fn has_caps() -> Result<bool> {
    let permitted = caps::read(None, caps::CapSet::Permitted)?;
    Ok(!permitted.is_empty())
}

/// Drop a single capability from the bounding set (safer wrapper)
fn drop_cap_bset(cap: u8) {
    // Ignore errors - capability might not exist or already dropped
    unsafe {
        libc::prctl(libc::PR_CAPBSET_DROP, cap as libc::c_ulong, 0, 0, 0);
    }
}

/// Drop capability bounding set
pub fn drop_cap_bounding_set(drop_all: bool) -> Result<()> {
    if !drop_all {
        return Ok(());
    }

    // Drop all capabilities from the bounding set
    // This prevents gaining new capabilities via setuid/setgid binaries
    // CAP_LAST_CAP is typically around 40-41 in modern kernels
    const CAP_LAST_CAP: u8 = 41;

    for cap in 0..=CAP_LAST_CAP {
        drop_cap_bset(cap);
    }

    Ok(())
}

/// Set ambient capabilities
pub fn set_ambient_capabilities() -> Result<()> {
    // Ambient capabilities allow unprivileged processes to retain capabilities
    // across execve when running with PR_SET_NO_NEW_PRIVS

    let caps_to_set = caps::read(None, caps::CapSet::Permitted)?;
    log::debug!("Setting ambient capabilities: {:?}", caps_to_set);

    caps::set(None, caps::CapSet::Ambient, &caps_to_set)
        .wrap_err("Failed to set ambient capabilities")?;
    log::debug!("Ambient capabilities set successfully");

    Ok(())
}

/// Set keep capabilities flag (safer wrapper around prctl)
fn set_keepcaps(keep: bool) -> Result<()> {
    unsafe {
        let ret = libc::prctl(libc::PR_SET_KEEPCAPS, if keep { 1 } else { 0 }, 0, 0, 0);
        if ret != 0 {
            eyre::bail!(
                "Failed to set PR_SET_KEEPCAPS: {}",
                std::io::Error::last_os_error()
            );
        }
    }
    Ok(())
}

/// Switch to user with privileges
pub fn switch_to_user(uid: Uid, gid: Gid, keep_caps: bool) -> Result<()> {
    // Set PR_SET_KEEPCAPS to retain capabilities across setuid
    if keep_caps {
        set_keepcaps(true)?;
    }

    setgid(gid).wrap_err("Failed to set GID")?;
    setuid(uid).wrap_err("Failed to set UID")?;

    Ok(())
}

/// Parse capability name and return Capability enum
fn parse_capability(cap_str: &str) -> Result<caps::Capability> {
    use caps::Capability;

    // Remove CAP_ prefix if present
    let cap_name = cap_str.trim().trim_start_matches("CAP_").to_uppercase();

    match cap_name.as_str() {
        "CHOWN" => Ok(Capability::CAP_CHOWN),
        "DAC_OVERRIDE" => Ok(Capability::CAP_DAC_OVERRIDE),
        "DAC_READ_SEARCH" => Ok(Capability::CAP_DAC_READ_SEARCH),
        "FOWNER" => Ok(Capability::CAP_FOWNER),
        "FSETID" => Ok(Capability::CAP_FSETID),
        "KILL" => Ok(Capability::CAP_KILL),
        "SETGID" => Ok(Capability::CAP_SETGID),
        "SETUID" => Ok(Capability::CAP_SETUID),
        "SETPCAP" => Ok(Capability::CAP_SETPCAP),
        "LINUX_IMMUTABLE" => Ok(Capability::CAP_LINUX_IMMUTABLE),
        "NET_BIND_SERVICE" => Ok(Capability::CAP_NET_BIND_SERVICE),
        "NET_BROADCAST" => Ok(Capability::CAP_NET_BROADCAST),
        "NET_ADMIN" => Ok(Capability::CAP_NET_ADMIN),
        "NET_RAW" => Ok(Capability::CAP_NET_RAW),
        "IPC_LOCK" => Ok(Capability::CAP_IPC_LOCK),
        "IPC_OWNER" => Ok(Capability::CAP_IPC_OWNER),
        "SYS_MODULE" => Ok(Capability::CAP_SYS_MODULE),
        "SYS_RAWIO" => Ok(Capability::CAP_SYS_RAWIO),
        "SYS_CHROOT" => Ok(Capability::CAP_SYS_CHROOT),
        "SYS_PTRACE" => Ok(Capability::CAP_SYS_PTRACE),
        "SYS_PACCT" => Ok(Capability::CAP_SYS_PACCT),
        "SYS_ADMIN" => Ok(Capability::CAP_SYS_ADMIN),
        "SYS_BOOT" => Ok(Capability::CAP_SYS_BOOT),
        "SYS_NICE" => Ok(Capability::CAP_SYS_NICE),
        "SYS_RESOURCE" => Ok(Capability::CAP_SYS_RESOURCE),
        "SYS_TIME" => Ok(Capability::CAP_SYS_TIME),
        "SYS_TTY_CONFIG" => Ok(Capability::CAP_SYS_TTY_CONFIG),
        "MKNOD" => Ok(Capability::CAP_MKNOD),
        "LEASE" => Ok(Capability::CAP_LEASE),
        "AUDIT_WRITE" => Ok(Capability::CAP_AUDIT_WRITE),
        "AUDIT_CONTROL" => Ok(Capability::CAP_AUDIT_CONTROL),
        "SETFCAP" => Ok(Capability::CAP_SETFCAP),
        "MAC_OVERRIDE" => Ok(Capability::CAP_MAC_OVERRIDE),
        "MAC_ADMIN" => Ok(Capability::CAP_MAC_ADMIN),
        "SYSLOG" => Ok(Capability::CAP_SYSLOG),
        "WAKE_ALARM" => Ok(Capability::CAP_WAKE_ALARM),
        "BLOCK_SUSPEND" => Ok(Capability::CAP_BLOCK_SUSPEND),
        "AUDIT_READ" => Ok(Capability::CAP_AUDIT_READ),
        "ALL" => eyre::bail!("CAP_ALL is not a real capability, use individual capabilities"),
        _ => eyre::bail!("Unknown capability: {}", cap_str),
    }
}

/// Add specific capabilities
pub fn add_capabilities(caps_to_add: &[String]) -> Result<()> {
    // Read current capabilities
    let mut permitted = caps::read(None, caps::CapSet::Permitted)?;
    let mut effective = caps::read(None, caps::CapSet::Effective)?;

    // Add requested capabilities to permitted and effective sets
    for cap_str in caps_to_add {
        let cap = parse_capability(cap_str)?;
        permitted.insert(cap);
        effective.insert(cap);
    }

    // Set the updated capability sets
    caps::set(None, caps::CapSet::Permitted, &permitted)
        .wrap_err("Failed to set permitted capabilities")?;
    caps::set(None, caps::CapSet::Effective, &effective)
        .wrap_err("Failed to set effective capabilities")?;

    Ok(())
}

/// Drop specific capabilities
pub fn drop_capabilities(caps_to_drop: &[String]) -> Result<()> {
    // Read current capabilities
    let mut permitted = caps::read(None, caps::CapSet::Permitted)?;
    let mut effective = caps::read(None, caps::CapSet::Effective)?;

    // Remove requested capabilities from permitted and effective sets
    for cap_str in caps_to_drop {
        let cap = parse_capability(cap_str)?;
        permitted.remove(&cap);
        effective.remove(&cap);
    }

    // Set the updated capability sets (skip inheritable - it's usually empty for root)
    // Order matters: set permitted first, then effective
    caps::set(None, caps::CapSet::Permitted, &permitted)
        .wrap_err("Failed to set permitted capabilities")?;
    caps::set(None, caps::CapSet::Effective, &effective)
        .wrap_err("Failed to set effective capabilities")?;

    Ok(())
}

/// Apply capability changes (add/drop) in one operation
/// This computes the final capability set and applies it atomically
pub fn apply_capability_changes(cap_add: &[String], cap_drop: &[String]) -> Result<()> {
    use std::collections::HashSet;

    // Start with current capabilities
    let current_permitted = caps::read(None, caps::CapSet::Permitted)?;
    log::debug!("Current permitted capabilities: {:?}", current_permitted);
    let mut final_caps: HashSet<_> = current_permitted.into_iter().collect();

    // Apply drops first (remove from set)
    for cap_str in cap_drop {
        let cap = parse_capability(cap_str)?;
        log::debug!("Dropping capability: {:?}", cap);
        final_caps.remove(&cap);
    }

    // Then apply adds
    for cap_str in cap_add {
        let cap = parse_capability(cap_str)?;
        log::debug!("Adding capability: {:?}", cap);
        final_caps.insert(cap);
    }

    log::debug!("Final capability set: {:?}", final_caps);

    // When removing capabilities, we need to drop from Effective first, then Permitted
    // When adding capabilities, we need to add to Permitted first, then Effective
    // To handle both cases, we clear Effective first, then set Permitted, then set Effective

    // Clear effective capabilities first
    log::debug!("Clearing effective capabilities");
    caps::clear(None, caps::CapSet::Effective)
        .wrap_err("Failed to clear effective capabilities")?;

    // Set permitted capabilities
    log::debug!("Setting permitted capabilities");
    caps::set(None, caps::CapSet::Permitted, &final_caps)
        .wrap_err("Failed to set permitted capabilities")?;

    // Set effective capabilities
    log::debug!("Setting effective capabilities");
    caps::set(None, caps::CapSet::Effective, &final_caps)
        .wrap_err("Failed to set effective capabilities")?;

    log::debug!("Capability changes applied successfully");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_has_caps() -> Result<()> {
        // This test will vary depending on whether we're running as root
        let _ = has_caps()?;
        Ok(())
    }
}
