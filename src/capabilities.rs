//! Capability management

use caps::Capability;
use eyre::{Context, Result};
use std::collections::HashSet;

/// Drop all capabilities
pub(crate) fn drop_all_caps() -> Result<()> {
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

/// Set ambient capabilities
pub(crate) fn set_ambient_capabilities() -> Result<()> {
    // Ambient capabilities allow unprivileged processes to retain capabilities
    // across execve when running with PR_SET_NO_NEW_PRIVS

    let caps_to_set = caps::read(None, caps::CapSet::Permitted)?;
    log::debug!("Setting ambient capabilities: {:?}", caps_to_set);

    caps::set(None, caps::CapSet::Ambient, &caps_to_set)
        .wrap_err("Failed to set ambient capabilities")?;
    log::debug!("Ambient capabilities set successfully");

    Ok(())
}

/// Parse capability name and return Capability enum
fn parse_capability(cap_str: &str) -> Result<caps::Capability> {
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

/// Apply capability changes (add/drop) in one operation
/// This computes the final capability set and applies it atomically
pub(crate) fn apply_capability_changes(cap_add: &[String], cap_drop: &[String]) -> Result<()> {
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
    fn test_parse_capability_basic() -> Result<()> {
        let cap = parse_capability("NET_ADMIN")?;
        assert_eq!(cap, caps::Capability::CAP_NET_ADMIN);
        Ok(())
    }

    #[test]
    fn test_parse_capability_with_prefix() -> Result<()> {
        let cap = parse_capability("CAP_NET_ADMIN")?;
        assert_eq!(cap, caps::Capability::CAP_NET_ADMIN);
        Ok(())
    }

    #[test]
    fn test_parse_capability_case_insensitive() -> Result<()> {
        assert_eq!(
            parse_capability("net_admin")?,
            caps::Capability::CAP_NET_ADMIN
        );
        assert_eq!(
            parse_capability("Net_Admin")?,
            caps::Capability::CAP_NET_ADMIN
        );
        assert_eq!(
            parse_capability("NET_ADMIN")?,
            caps::Capability::CAP_NET_ADMIN
        );
        Ok(())
    }

    #[test]
    fn test_parse_capability_whitespace() -> Result<()> {
        let cap = parse_capability("  NET_ADMIN  ")?;
        assert_eq!(cap, caps::Capability::CAP_NET_ADMIN);
        Ok(())
    }

    #[test]
    fn test_parse_capability_invalid() {
        let result = parse_capability("INVALID_CAP_NAME");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Unknown capability")
        );
    }

    #[test]
    fn test_parse_capability_rejects_cap_all() {
        let result = parse_capability("ALL");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("CAP_ALL"));
    }

    #[test]
    fn test_parse_capability_rejects_cap_all_with_prefix() {
        let result = parse_capability("CAP_ALL");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_all_documented_capabilities() -> Result<()> {
        // Test that all capabilities we document actually parse
        let capabilities = vec![
            "CHOWN",
            "DAC_OVERRIDE",
            "DAC_READ_SEARCH",
            "FOWNER",
            "FSETID",
            "KILL",
            "SETGID",
            "SETUID",
            "SETPCAP",
            "LINUX_IMMUTABLE",
            "NET_BIND_SERVICE",
            "NET_BROADCAST",
            "NET_ADMIN",
            "NET_RAW",
            "IPC_LOCK",
            "IPC_OWNER",
            "SYS_MODULE",
            "SYS_RAWIO",
            "SYS_CHROOT",
            "SYS_PTRACE",
            "SYS_PACCT",
            "SYS_ADMIN",
            "SYS_BOOT",
            "SYS_NICE",
            "SYS_RESOURCE",
            "SYS_TIME",
            "SYS_TTY_CONFIG",
            "MKNOD",
            "LEASE",
            "AUDIT_WRITE",
            "AUDIT_CONTROL",
            "SETFCAP",
            "MAC_OVERRIDE",
            "MAC_ADMIN",
            "SYSLOG",
            "WAKE_ALARM",
            "BLOCK_SUSPEND",
            "AUDIT_READ",
        ];

        for cap in capabilities {
            parse_capability(cap)?;
        }

        Ok(())
    }
}
