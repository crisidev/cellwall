//! Network namespace setup

use eyre::{Context, Result};
use nix::sys::socket::{AddressFamily, SockFlag, SockType, socket};
use std::os::unix::io::{AsRawFd, RawFd};

const LOOPBACK_IFNAME: &str = "lo";

/// Set up loopback interface in the network namespace
pub fn setup_loopback() -> Result<()> {
    log::debug!("Setting up loopback interface");
    // Create a netlink socket
    let sock = socket(
        AddressFamily::Netlink,
        SockType::Raw,
        SockFlag::SOCK_CLOEXEC,
        None,
    )
    .wrap_err("Failed to create netlink socket")?;
    log::debug!("Created netlink socket");

    // Bring up the loopback interface
    log::debug!("Bringing up interface: {}", LOOPBACK_IFNAME);
    bring_up_interface(sock.as_raw_fd(), LOOPBACK_IFNAME)?;
    log::debug!("Loopback interface is up");

    Ok(())
}

/// Bring up a network interface
fn bring_up_interface(sock: RawFd, ifname: &str) -> Result<()> {
    use nix::libc::{IFF_UP, SIOCSIFFLAGS, ifreq};
    use std::ffi::CString;
    use std::mem;

    log::debug!("Using ioctl SIOCSIFFLAGS to set IFF_UP on {}", ifname);

    // This is a simplified version - full implementation would use netlink
    // For now, we use ioctl to bring up the interface
    unsafe {
        let mut ifr: ifreq = mem::zeroed();
        let name = CString::new(ifname)?;
        let name_bytes = name.as_bytes_with_nul();

        // Copy interface name
        let len = name_bytes.len().min(ifr.ifr_name.len());
        for (i, &byte) in name_bytes.iter().take(len).enumerate() {
            ifr.ifr_name[i] = byte as i8;
        }

        // Set the UP flag
        ifr.ifr_ifru.ifru_flags = IFF_UP as i16;

        // Use ioctl to set interface flags
        log::debug!("Calling ioctl(SIOCSIFFLAGS) on socket {}", sock);
        let ret = nix::libc::ioctl(sock, SIOCSIFFLAGS, &ifr);
        if ret < 0 {
            eyre::bail!("Failed to bring up interface {}", ifname);
        }
        log::debug!("ioctl succeeded, interface {} is now UP", ifname);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_constant() {
        assert_eq!(LOOPBACK_IFNAME, "lo");
    }
}
