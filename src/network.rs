//! Network namespace setup

use eyre::Result;
use std::mem;

const LOOPBACK_IFNAME: &str = "lo";

// Netlink constants
const NETLINK_ROUTE: i32 = 0;
const RTM_NEWADDR: u16 = 20;
const RTM_NEWLINK: u16 = 16;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_EXCL: u16 = 0x0200;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;

// Routing constants
const AF_INET: u8 = 2;
const AF_UNSPEC: u8 = 0;
const RT_SCOPE_HOST: u8 = 254;
const IFA_F_PERMANENT: u32 = 0x80;
const IFA_LOCAL: u16 = 2;
const IFA_ADDRESS: u16 = 1;
const IFF_UP: i16 = 1;

// Netlink message structures
#[repr(C)]
struct nlmsghdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
struct rtattr {
    rta_len: u16,
    rta_type: u16,
}

#[repr(C)]
struct ifaddrmsg {
    ifa_family: u8,
    ifa_prefixlen: u8,
    ifa_flags: u8,
    ifa_scope: u8,
    ifa_index: i32,
}

#[repr(C)]
struct ifinfomsg {
    ifi_family: u8,
    __ifi_pad: u8,
    ifi_type: u16,
    ifi_index: i32,
    ifi_flags: u32,
    ifi_change: u32,
}

#[repr(C)]
struct sockaddr_nl {
    nl_family: u16, // AF_NETLINK
    nl_pad: u16,
    nl_pid: u32,
    nl_groups: u32,
}

// Helper macros (matching kernel netlink.h)
const fn nlmsg_align(len: usize) -> usize {
    (len + 3) & !3
}

const fn nlmsg_length(len: usize) -> u32 {
    (nlmsg_align(mem::size_of::<nlmsghdr>()) + len) as u32
}

const fn rta_length(len: usize) -> u16 {
    (nlmsg_align(mem::size_of::<rtattr>()) + len) as u16
}

const fn nlmsg_hdrlen() -> usize {
    nlmsg_align(mem::size_of::<nlmsghdr>())
}

/// Set up loopback interface in the network namespace
/// Based on bubblewrap's loopback_setup function in network.c
pub fn setup_loopback() -> Result<()> {
    log::debug!("Setting up loopback interface with netlink");

    // Get loopback interface index
    let if_loopback = unsafe {
        let ifname = std::ffi::CString::new(LOOPBACK_IFNAME)?;
        let index = libc::if_nametoindex(ifname.as_ptr());
        if index == 0 {
            eyre::bail!("Failed to look up loopback interface 'lo'");
        }
        index as i32
    };
    log::debug!("Loopback interface index: {}", if_loopback);

    // Create netlink socket
    let sock = unsafe {
        let fd = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        );
        if fd < 0 {
            eyre::bail!("Failed to create NETLINK_ROUTE socket");
        }
        fd
    };
    log::debug!("Created netlink socket: {}", sock);

    // Bind the socket
    let src_addr = sockaddr_nl {
        nl_family: libc::AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: unsafe { libc::getpid() as u32 },
        nl_groups: 0,
    };

    unsafe {
        let ret = libc::bind(
            sock,
            &src_addr as *const sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<sockaddr_nl>() as u32,
        );
        if ret < 0 {
            libc::close(sock);
            eyre::bail!("Failed to bind NETLINK_ROUTE socket");
        }
    }
    log::debug!("Bound netlink socket");

    // Sequence number counter (static in bubblewrap)
    static mut SEQ_COUNTER: u32 = 0;
    let seq = unsafe {
        SEQ_COUNTER += 1;
        SEQ_COUNTER
    };

    // Step 1: Add IP address 127.0.0.1 to loopback interface
    log::debug!("Adding IP address 127.0.0.1/8 to loopback interface");
    add_loopback_address(sock, if_loopback, seq)?;

    // Step 2: Bring the interface UP
    log::debug!("Bringing loopback interface UP");
    bring_loopback_up(sock, if_loopback, seq + 1)?;

    // Close socket
    unsafe {
        libc::close(sock);
    }
    log::debug!("Loopback interface setup complete");

    Ok(())
}

/// Add IP address to loopback interface using RTM_NEWADDR
fn add_loopback_address(sock: i32, if_index: i32, seq: u32) -> Result<()> {
    let mut buffer = vec![0u8; 1024];

    // Setup nlmsghdr
    let addmsg_size = mem::size_of::<ifaddrmsg>();
    let mut len = nlmsg_length(addmsg_size);

    let header = unsafe { &mut *(buffer.as_mut_ptr() as *mut nlmsghdr) };
    header.nlmsg_len = len;
    header.nlmsg_type = RTM_NEWADDR;
    header.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    header.nlmsg_seq = seq;
    header.nlmsg_pid = unsafe { libc::getpid() as u32 };

    // Setup ifaddrmsg
    let addmsg = unsafe { &mut *(buffer.as_mut_ptr().add(nlmsg_hdrlen()) as *mut ifaddrmsg) };
    addmsg.ifa_family = AF_INET;
    addmsg.ifa_prefixlen = 8;
    addmsg.ifa_flags = 0;
    addmsg.ifa_scope = RT_SCOPE_HOST;
    addmsg.ifa_index = if_index;

    // Add IFA_LOCAL attribute with 127.0.0.1
    let ip_addr: u32 = u32::to_be(0x7f000001); // 127.0.0.1 in network byte order
    len = add_rta(&mut buffer, len as usize, IFA_LOCAL, &ip_addr)? as u32;

    // Add IFA_ADDRESS attribute with 127.0.0.1
    len = add_rta(&mut buffer, len as usize, IFA_ADDRESS, &ip_addr)? as u32;

    // Update header length
    let header = unsafe { &mut *(buffer.as_mut_ptr() as *mut nlmsghdr) };
    header.nlmsg_len = len;

    log::debug!("Sending RTM_NEWADDR message (len={}, seq={})", len, seq);

    // Send request
    rtnl_do_request(sock, &buffer[..len as usize], seq)?;

    log::debug!("Successfully added IP address to loopback");
    Ok(())
}

/// Bring loopback interface UP using RTM_NEWLINK
fn bring_loopback_up(sock: i32, if_index: i32, seq: u32) -> Result<()> {
    let mut buffer = vec![0u8; 1024];

    // Setup nlmsghdr
    let infomsg_size = mem::size_of::<ifinfomsg>();
    let len = nlmsg_length(infomsg_size);

    let header = unsafe { &mut *(buffer.as_mut_ptr() as *mut nlmsghdr) };
    header.nlmsg_len = len;
    header.nlmsg_type = RTM_NEWLINK;
    header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    header.nlmsg_seq = seq;
    header.nlmsg_pid = unsafe { libc::getpid() as u32 };

    // Setup ifinfomsg
    let infomsg = unsafe { &mut *(buffer.as_mut_ptr().add(nlmsg_hdrlen()) as *mut ifinfomsg) };
    infomsg.ifi_family = AF_UNSPEC;
    infomsg.__ifi_pad = 0;
    infomsg.ifi_type = 0;
    infomsg.ifi_index = if_index;
    infomsg.ifi_flags = IFF_UP as u32;
    infomsg.ifi_change = IFF_UP as u32;

    log::debug!("Sending RTM_NEWLINK message (len={}, seq={})", len, seq);

    // Send request
    rtnl_do_request(sock, &buffer[..len as usize], seq)?;

    log::debug!("Successfully brought loopback interface UP");
    Ok(())
}

/// Add a routing attribute to the netlink message
fn add_rta<T>(buffer: &mut Vec<u8>, current_len: usize, rta_type: u16, data: &T) -> Result<usize> {
    let data_size = mem::size_of::<T>();
    let rta_size = rta_length(data_size) as usize;
    let aligned_current = nlmsg_align(current_len);

    // Ensure buffer has enough space
    let new_len = aligned_current + rta_size;
    if buffer.len() < new_len {
        buffer.resize(new_len, 0);
    }

    // Write rtattr header
    let rta = unsafe { &mut *(buffer.as_mut_ptr().add(aligned_current) as *mut rtattr) };
    rta.rta_type = rta_type;
    rta.rta_len = rta_size as u16;

    // Write data
    let data_offset = aligned_current + nlmsg_align(mem::size_of::<rtattr>());
    unsafe {
        std::ptr::copy_nonoverlapping(
            data as *const T as *const u8,
            buffer.as_mut_ptr().add(data_offset),
            data_size,
        );
    }

    Ok(new_len)
}

/// Send netlink request and wait for reply
fn rtnl_do_request(sock: i32, buffer: &[u8], seq: u32) -> Result<()> {
    // Send request
    let dst_addr = sockaddr_nl {
        nl_family: libc::AF_NETLINK as u16,
        nl_pad: 0,
        nl_pid: 0,
        nl_groups: 0,
    };

    let sent = unsafe {
        libc::sendto(
            sock,
            buffer.as_ptr() as *const libc::c_void,
            buffer.len(),
            0,
            &dst_addr as *const sockaddr_nl as *const libc::sockaddr,
            mem::size_of::<sockaddr_nl>() as u32,
        )
    };

    if sent < 0 {
        eyre::bail!("Failed to send netlink request");
    }

    log::debug!("Sent {} bytes to netlink", sent);

    // Read reply
    rtnl_read_reply(sock, seq)?;

    Ok(())
}

/// Read and validate netlink reply
fn rtnl_read_reply(sock: i32, expected_seq: u32) -> Result<()> {
    let mut buffer = vec![0u8; 1024];

    loop {
        let received = unsafe {
            libc::recv(
                sock,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };

        if received < 0 {
            eyre::bail!("Failed to receive netlink reply");
        }

        log::debug!("Received {} bytes from netlink", received);

        let mut offset = 0;
        while offset + mem::size_of::<nlmsghdr>() <= received as usize {
            let header = unsafe { &*(buffer.as_ptr().add(offset) as *const nlmsghdr) };

            // Verify sequence number
            if header.nlmsg_seq != expected_seq {
                eyre::bail!(
                    "Unexpected sequence number: got {}, expected {}",
                    header.nlmsg_seq,
                    expected_seq
                );
            }

            // Verify PID
            let pid = unsafe { libc::getpid() as u32 };
            if header.nlmsg_pid != pid {
                eyre::bail!(
                    "Unexpected PID in reply: got {}, expected {}",
                    header.nlmsg_pid,
                    pid
                );
            }

            // Handle message type
            match header.nlmsg_type {
                NLMSG_ERROR => {
                    // Check error code
                    let error_offset = offset + nlmsg_hdrlen();
                    if error_offset + mem::size_of::<i32>() <= received as usize {
                        let error_code =
                            unsafe { *(buffer.as_ptr().add(error_offset) as *const i32) };
                        if error_code == 0 {
                            log::debug!("Netlink operation successful (ACK)");
                            return Ok(());
                        } else {
                            eyre::bail!("Netlink error: {}", error_code);
                        }
                    }
                    eyre::bail!("Invalid NLMSG_ERROR message");
                }
                NLMSG_DONE => {
                    log::debug!("Netlink operation complete (DONE)");
                    return Ok(());
                }
                _ => {
                    log::debug!("Unexpected netlink message type: {}", header.nlmsg_type);
                }
            }

            // Move to next message
            let aligned_len = nlmsg_align(header.nlmsg_len as usize);
            offset += aligned_len;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loopback_constant() {
        assert_eq!(LOOPBACK_IFNAME, "lo");
    }

    #[test]
    fn test_nlmsg_align() {
        assert_eq!(nlmsg_align(0), 0);
        assert_eq!(nlmsg_align(1), 4);
        assert_eq!(nlmsg_align(2), 4);
        assert_eq!(nlmsg_align(3), 4);
        assert_eq!(nlmsg_align(4), 4);
        assert_eq!(nlmsg_align(5), 8);
    }

    #[test]
    fn test_ip_address_encoding() {
        let ip_addr: u32 = u32::to_be(0x7f000001); // 127.0.0.1
        assert_eq!(ip_addr, 0x0100007f); // Network byte order (big-endian)
    }
}
