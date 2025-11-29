//! KCP Proxy Module for VNT (Stub Implementation)
//!
//! This module provides KCP-based TCP proxy functionality.
//! Currently a stub implementation - full functionality to be added later.

use std::io;
use std::net::Ipv4Addr;

use crate::channel::context::ChannelContext;
use crate::ip_proxy::ProxyHandler;
use packet::ip::ipv4::packet::IpV4Packet;

/// KCP Proxy Source - handles outgoing connections through KCP
pub struct KcpProxySrc;

/// KCP Proxy Destination - handles incoming KCP connections  
pub struct KcpProxyDst;

/// Combined KCP Proxy that handles both source and destination
#[derive(Clone)]
pub struct KcpProxy {
    enabled: bool,
}

impl KcpProxy {
    pub async fn new(_context: ChannelContext, enable_src: bool, enable_dst: bool) -> anyhow::Result<Self> {
        log::info!("KCP proxy initialized (stub) - src: {}, dst: {}", enable_src, enable_dst);
        Ok(Self {
            enabled: enable_src || enable_dst,
        })
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl ProxyHandler for KcpProxy {
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
