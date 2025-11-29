//! QUIC Proxy Module for VNT (Stub Implementation)
//!
//! This module provides QUIC-based TCP proxy functionality.
//! Currently a stub implementation - full functionality to be added later.

use std::io;
use std::net::Ipv4Addr;

use crate::channel::context::ChannelContext;
use crate::ip_proxy::ProxyHandler;
use packet::ip::ipv4::packet::IpV4Packet;

/// QUIC Proxy Source - initiates QUIC connections to peers
pub struct QuicProxySrc;

/// QUIC Proxy Destination - accepts QUIC connections from peers
pub struct QuicProxyDst;

/// Combined QUIC Proxy that handles both source and destination
#[derive(Clone)]
pub struct QuicProxy {
    enabled: bool,
    local_port: u16,
}

impl QuicProxy {
    pub async fn new(
        _context: ChannelContext,
        enable_src: bool,
        enable_dst: bool,
        listen_port: u16,
    ) -> anyhow::Result<Self> {
        log::info!("QUIC proxy initialized (stub) - src: {}, dst: {}, port: {}", enable_src, enable_dst, listen_port);
        Ok(Self {
            enabled: enable_src || enable_dst,
            local_port: listen_port,
        })
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl ProxyHandler for QuicProxy {
    fn recv_handle(
        &self,
        _ipv4: &mut IpV4Packet<&mut [u8]>,
        _source: Ipv4Addr,
        _destination: Ipv4Addr,
    ) -> io::Result<bool> {
        Ok(false)
    }

    fn send_handle(&self, _ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        Ok(())
    }
}
