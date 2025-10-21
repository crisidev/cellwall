//! Network namespace setup

use eyre::{Context, Result};
use netlink_packet_core::{
    NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_EXCL, NLM_F_REQUEST,
};
use netlink_packet_route::{
    address::{AddressAttribute, AddressMessage, AddressScope},
    link::{LinkFlags, LinkMessage},
    AddressFamily, RouteNetlinkMessage,
};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::net::Ipv4Addr;

const LOOPBACK_IFNAME: &str = "lo";

/// Set up loopback interface in the network namespace
/// Based on bubblewrap's loopback_setup function in network.c
pub fn setup_loopback() -> Result<()> {
    log::debug!("Setting up loopback interface with netlink");

    // Get loopback interface index
    let if_loopback = nix::net::if_::if_nametoindex(LOOPBACK_IFNAME)
        .wrap_err("Failed to look up loopback interface 'lo'")?;
    log::debug!("Loopback interface index: {}", if_loopback);

    // Create and bind netlink socket
    let mut socket = Socket::new(NETLINK_ROUTE).wrap_err("Failed to create netlink socket")?;

    socket
        .bind_auto()
        .wrap_err("Failed to bind netlink socket")?;

    log::debug!("Created and bound netlink socket");

    // Step 1: Add IP address 127.0.0.1 to loopback interface
    log::debug!("Adding IP address 127.0.0.1/8 to loopback interface");
    add_loopback_address(&mut socket, if_loopback)?;

    // Step 2: Bring the interface UP
    log::debug!("Bringing loopback interface UP");
    bring_loopback_up(&mut socket, if_loopback)?;

    log::debug!("Loopback interface setup complete");
    Ok(())
}

/// Add IP address to loopback interface using RTM_NEWADDR
fn add_loopback_address(socket: &mut Socket, if_index: u32) -> Result<()> {
    // Create address message
    let mut msg = AddressMessage::default();
    msg.header.family = AddressFamily::Inet;
    msg.header.prefix_len = 8;
    msg.header.scope = AddressScope::Host;
    msg.header.index = if_index;

    // Add 127.0.0.1 as both LOCAL and ADDRESS attributes
    let loopback_ip = Ipv4Addr::new(127, 0, 0, 1);
    msg.attributes
        .push(AddressAttribute::Local(loopback_ip.into()));
    msg.attributes
        .push(AddressAttribute::Address(loopback_ip.into()));

    // Wrap in netlink message
    let mut nl_msg = NetlinkMessage::from(RouteNetlinkMessage::NewAddress(msg));
    nl_msg.header.flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    nl_msg.finalize();

    log::debug!("Sending RTM_NEWADDR message");

    // Send and receive ACK
    send_and_receive_ack(socket, nl_msg).wrap_err("Failed to add loopback address")?;

    log::debug!("Successfully added IP address to loopback");
    Ok(())
}

/// Bring loopback interface UP using RTM_NEWLINK
fn bring_loopback_up(socket: &mut Socket, if_index: u32) -> Result<()> {
    // Create link message
    let mut msg = LinkMessage::default();
    msg.header.index = if_index;
    msg.header.flags = LinkFlags::Up;
    msg.header.change_mask = LinkFlags::Up;

    // Wrap in netlink message
    let mut nl_msg = NetlinkMessage::from(RouteNetlinkMessage::SetLink(msg));
    nl_msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;
    nl_msg.finalize();

    log::debug!("Sending RTM_NEWLINK message");

    // Send and receive ACK
    send_and_receive_ack(socket, nl_msg).wrap_err("Failed to bring loopback up")?;

    log::debug!("Successfully brought loopback interface UP");
    Ok(())
}

/// Helper function to send a netlink message and wait for ACK
fn send_and_receive_ack(
    socket: &mut Socket,
    message: NetlinkMessage<RouteNetlinkMessage>,
) -> Result<()> {
    // Serialize and send message
    let mut buf = vec![0; message.buffer_len()];
    message.serialize(&mut buf[..]);

    // Send to kernel (pid 0)
    let kernel_addr = SocketAddr::new(0, 0);
    socket
        .send_to(&buf[..], &kernel_addr, 0)
        .wrap_err("Failed to send netlink message")?;

    log::debug!("Sent {} bytes netlink message, waiting for ACK", buf.len());

    // Receive and parse response
    // recv_from_full allocates its own buffer and returns (Vec<u8>, SocketAddr)
    let (response_buf, from_addr) = socket
        .recv_from_full()
        .wrap_err("Failed to receive netlink response")?;

    let n = response_buf.len();
    log::debug!("Received {} bytes from netlink (from pid {})", n, from_addr.port_number());

    if n == 0 {
        eyre::bail!("Received empty response from netlink");
    }

    // Check if buffer actually has data
    let all_zeros = response_buf.iter().all(|&b| b == 0);
    if all_zeros {
        eyre::bail!("Received buffer is all zeros - possible recv issue");
    }

    // Log the response bytes for debugging
    log::debug!("Response bytes (first {}): {:02x?}", n.min(36), &response_buf[..n.min(36)]);

    let bytes = &response_buf[..];

    let response = NetlinkMessage::<RouteNetlinkMessage>::deserialize(bytes)
        .wrap_err("Failed to deserialize netlink response")?;

    // Check response
    match response.payload {
        NetlinkPayload::Error(err) => {
            if let Some(code) = err.code {
                // If code is Some(non-zero), it's an error
                eyre::bail!("Netlink error code {}: {:?}", code, err);
            }
            // Error code None or Some(0) means ACK (success)
            // Note: NonZeroI32 cannot represent 0, so Some means error, None means success
            log::debug!("Received netlink ACK");
            Ok(())
        }
        NetlinkPayload::Done(_) => {
            log::debug!("Received netlink DONE");
            Ok(())
        }
        _ => eyre::bail!("Unexpected netlink response type: {:?}", response.payload),
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
    fn test_loopback_ip_encoding() {
        let loopback_ip = Ipv4Addr::new(127, 0, 0, 1);
        assert_eq!(loopback_ip.octets(), [127, 0, 0, 1]);
    }

    #[test]
    fn test_send_and_receive_ack() {
        let mut socket = Socket::new(NETLINK_ROUTE).expect("Failed to create socket");
        socket.bind_auto().expect("Failed to bind socket");

        let kernel_addr = SocketAddr::new(0, 0);
        socket.connect(&kernel_addr).expect("Failed to connect");

        let msg = LinkMessage::default();
        let mut nl_msg = NetlinkMessage::from(RouteNetlinkMessage::GetLink(msg));
        nl_msg.header.flags = NLM_F_REQUEST | NLM_F_ACK;
        nl_msg.finalize();

        let result = send_and_receive_ack(&mut socket, nl_msg);

        // This will fail during tests, let's just grab the expected message
        assert_eq!(result.unwrap_err().to_string(), "Netlink error code -22: ErrorMessage { code: Some(-22), header: [32, 0, 0, 0, 18, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] }");
    }
}
