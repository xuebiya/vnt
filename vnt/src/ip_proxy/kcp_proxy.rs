//! KCP Proxy Module for VNT
//!
//! This module provides KCP (KCP Protocol) based TCP proxy functionality,
//! ported from EasyTier's kcp_proxy implementation.
//!
//! KCP provides reliable, ordered delivery over UDP with configurable
//! parameters for latency vs bandwidth tradeoff.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use dashmap::DashMap;
use kcp_sys::endpoint::{ConnId, KcpEndpoint, KcpPacketReceiver};
use kcp_sys::ffi_safe::KcpConfig;
use kcp_sys::packet_def::KcpPacket;
use kcp_sys::stream::KcpStream;
use parking_lot::Mutex;
use tokio::io::copy_bidirectional;
use tokio::net::TcpSocket;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::channel::context::ChannelContext;
use crate::channel::RouteKey;
use crate::ip_proxy::ProxyHandler;
use crate::protocol::NetPacket;
use packet::ip::ipv4::packet::IpV4Packet;

/// KCP connection data for establishing proxy connections
#[derive(Clone, Debug)]
pub struct KcpConnData {
    pub src: SocketAddr,
    pub dst: SocketAddr,
}

impl KcpConnData {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(36);
        // Encode src address
        match self.src {
            SocketAddr::V4(addr) => {
                buf.push(4); // IPv4 marker
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                buf.push(6); // IPv6 marker
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
        // Encode dst address
        match self.dst {
            SocketAddr::V4(addr) => {
                buf.push(4);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
            SocketAddr::V6(addr) => {
                buf.push(6);
                buf.extend_from_slice(&addr.ip().octets());
                buf.extend_from_slice(&addr.port().to_be_bytes());
            }
        }
        buf
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 14 {
            return None;
        }
        let mut offset = 0;

        // Decode src
        let src = if buf[offset] == 4 {
            offset += 1;
            let ip = Ipv4Addr::new(buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]);
            offset += 4;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            offset += 2;
            SocketAddr::V4(SocketAddrV4::new(ip, port))
        } else {
            return None; // Only support IPv4 for now
        };

        // Decode dst
        let dst = if buf[offset] == 4 {
            offset += 1;
            let ip = Ipv4Addr::new(buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]);
            offset += 4;
            let port = u16::from_be_bytes([buf[offset], buf[offset + 1]]);
            SocketAddr::V4(SocketAddrV4::new(ip, port))
        } else {
            return None;
        };

        Some(KcpConnData { src, dst })
    }
}

/// KCP packet type markers for routing
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KcpPacketType {
    /// Packet from source (client) side
    KcpSrc = 0x10,
    /// Packet from destination (server) side
    KcpDst = 0x11,
}

impl From<u8> for KcpPacketType {
    fn from(value: u8) -> Self {
        match value {
            0x10 => KcpPacketType::KcpSrc,
            0x11 => KcpPacketType::KcpDst,
            _ => KcpPacketType::KcpSrc,
        }
    }
}

/// Create a KCP endpoint with turbo configuration
fn create_kcp_endpoint() -> KcpEndpoint {
    let mut kcp_endpoint = KcpEndpoint::new();
    kcp_endpoint.set_kcp_config_factory(Box::new(|conv| {
        let mut cfg = KcpConfig::new_turbo(conv);
        cfg.interval = Some(5);
        cfg
    }));
    kcp_endpoint
}

/// NAT entry for tracking KCP proxy connections
#[derive(Debug)]
struct KcpNatEntry {
    src: SocketAddr,
    dst: SocketAddr,
    conn_id: ConnId,
    start_time: std::time::Instant,
}

/// KCP Proxy Source - handles outgoing connections through KCP
pub struct KcpProxySrc {
    kcp_endpoint: Arc<KcpEndpoint>,
    context: ChannelContext,
    nat_map: Arc<DashMap<SocketAddrV4, KcpNatEntry>>,
    local_port: u16,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl KcpProxySrc {
    pub async fn new(context: ChannelContext) -> anyhow::Result<Self> {
        let mut kcp_endpoint = create_kcp_endpoint();
        kcp_endpoint.run().await;

        let kcp_endpoint = Arc::new(kcp_endpoint);
        let nat_map = Arc::new(DashMap::new());
        let tasks = Arc::new(Mutex::new(JoinSet::new()));

        // Start output handler
        if let Some(output_receiver) = kcp_endpoint.output_receiver() {
            let context_clone = context.clone();
            let is_src = true;
            tasks.lock().spawn(handle_kcp_output(
                context_clone,
                output_receiver,
                is_src,
            ));
        }

        Ok(Self {
            kcp_endpoint,
            context,
            nat_map,
            local_port: 0, // Will be set when listener starts
            tasks,
        })
    }

    /// Process incoming KCP packet from peer
    pub async fn process_kcp_packet(&self, data: &[u8], _route_key: RouteKey) -> bool {
        if let Err(e) = self
            .kcp_endpoint
            .input_sender_ref()
            .send(KcpPacket::from(Bytes::copy_from_slice(data)))
            .await
        {
            log::error!("Failed to send KCP packet to endpoint: {:?}", e);
            return false;
        }
        true
    }

    /// Connect to a destination through KCP
    pub async fn connect(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        dst_peer_id: u32,
    ) -> anyhow::Result<KcpStream> {
        let conn_data = KcpConnData { src, dst };
        let my_peer_id = 0u32; // TODO: Get from context

        let conn_id = self
            .kcp_endpoint
            .connect(
                Duration::from_secs(10),
                my_peer_id,
                dst_peer_id,
                Bytes::from(conn_data.encode()),
            )
            .await?;

        let stream = KcpStream::new(&self.kcp_endpoint, conn_id)
            .ok_or_else(|| anyhow::anyhow!("Failed to create KCP stream"))?;

        Ok(stream)
    }

    pub fn get_kcp_endpoint(&self) -> Arc<KcpEndpoint> {
        self.kcp_endpoint.clone()
    }
}

/// KCP Proxy Destination - handles incoming KCP connections
pub struct KcpProxyDst {
    kcp_endpoint: Arc<KcpEndpoint>,
    context: ChannelContext,
    proxy_entries: Arc<DashMap<ConnId, KcpNatEntry>>,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl KcpProxyDst {
    pub async fn new(context: ChannelContext) -> anyhow::Result<Self> {
        let mut kcp_endpoint = create_kcp_endpoint();
        kcp_endpoint.run().await;

        let kcp_endpoint = Arc::new(kcp_endpoint);
        let proxy_entries = Arc::new(DashMap::new());
        let tasks = Arc::new(Mutex::new(JoinSet::new()));

        // Start output handler
        if let Some(output_receiver) = kcp_endpoint.output_receiver() {
            let context_clone = context.clone();
            let is_src = false;
            tasks.lock().spawn(handle_kcp_output(
                context_clone,
                output_receiver,
                is_src,
            ));
        }

        Ok(Self {
            kcp_endpoint,
            context,
            proxy_entries,
            tasks,
        })
    }

    /// Start accepting KCP connections
    pub async fn start(&self) {
        let kcp_endpoint = self.kcp_endpoint.clone();
        let proxy_entries = self.proxy_entries.clone();

        self.tasks.lock().spawn(async move {
            loop {
                match kcp_endpoint.accept().await {
                    Ok(conn_id) => {
                        let stream = match KcpStream::new(&kcp_endpoint, conn_id) {
                            Some(s) => s,
                            None => {
                                log::error!("Failed to create KCP stream for conn_id: {:?}", conn_id);
                                continue;
                            }
                        };

                        let proxy_entries_clone = proxy_entries.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                Self::handle_incoming_stream(stream, proxy_entries_clone).await
                            {
                                log::error!("Error handling KCP stream: {:?}", e);
                            }
                        });
                    }
                    Err(e) => {
                        log::error!("KCP accept error: {:?}", e);
                        break;
                    }
                }
            }
        });
    }

    /// Process incoming KCP packet from peer
    pub async fn process_kcp_packet(&self, data: &[u8], _route_key: RouteKey) -> bool {
        if let Err(e) = self
            .kcp_endpoint
            .input_sender_ref()
            .send(KcpPacket::from(Bytes::copy_from_slice(data)))
            .await
        {
            log::error!("Failed to send KCP packet to endpoint: {:?}", e);
            return false;
        }
        true
    }

    async fn handle_incoming_stream(
        kcp_stream: KcpStream,
        proxy_entries: Arc<DashMap<ConnId, KcpNatEntry>>,
    ) -> anyhow::Result<()> {
        let conn_data_bytes = kcp_stream.conn_data().clone();
        let conn_data = KcpConnData::decode(&conn_data_bytes)
            .ok_or_else(|| anyhow::anyhow!("Failed to decode KCP connection data"))?;

        let conn_id = kcp_stream.conn_id();
        proxy_entries.insert(
            conn_id,
            KcpNatEntry {
                src: conn_data.src,
                dst: conn_data.dst,
                conn_id,
                start_time: std::time::Instant::now(),
            },
        );

        // Connect to the actual destination
        let socket = TcpSocket::new_v4()?;
        let dst_stream = timeout(Duration::from_secs(10), socket.connect(conn_data.dst))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        // Proxy data bidirectionally
        let mut kcp_stream = kcp_stream;
        let mut dst_stream = dst_stream;

        if let Err(e) = copy_bidirectional(&mut kcp_stream, &mut dst_stream).await {
            log::debug!("KCP proxy connection closed: {:?}", e);
        }

        // Cleanup
        proxy_entries.remove(&conn_id);

        Ok(())
    }

    pub fn get_kcp_endpoint(&self) -> Arc<KcpEndpoint> {
        self.kcp_endpoint.clone()
    }
}

/// Handle KCP output packets and send them to peers
async fn handle_kcp_output(
    context: ChannelContext,
    mut output_receiver: KcpPacketReceiver,
    is_src: bool,
) {
    while let Some(packet) = output_receiver.recv().await {
        let dst_peer_id = if is_src {
            packet.header().dst_session_id()
        } else {
            packet.header().src_session_id()
        };

        let packet_type = if is_src {
            KcpPacketType::KcpSrc
        } else {
            KcpPacketType::KcpDst
        };

        // Create VNT packet with KCP data
        let kcp_data = packet.inner().freeze();
        let mut buf = vec![0u8; 12 + 1 + kcp_data.len()]; // VNT header + type + data

        if let Ok(mut net_packet) = NetPacket::new0(buf.len(), &mut buf[..]) {
            net_packet.set_default_version();
            net_packet.set_protocol(crate::protocol::Protocol::OtherTurn);
            net_packet.set_transport_protocol(packet_type as u8);

            let payload = net_packet.payload_mut();
            payload[0] = packet_type as u8;
            payload[1..].copy_from_slice(&kcp_data);

            // Send to peer - this would need proper routing
            // For now, we log the attempt
            log::trace!(
                "KCP output packet for peer {}, type: {:?}, len: {}",
                dst_peer_id,
                packet_type,
                kcp_data.len()
            );
        }
    }
}

/// Combined KCP Proxy that handles both source and destination
#[derive(Clone)]
pub struct KcpProxy {
    src_proxy: Option<Arc<KcpProxySrc>>,
    dst_proxy: Option<Arc<KcpProxyDst>>,
    enabled: bool,
}

impl KcpProxy {
    pub async fn new(context: ChannelContext, enable_src: bool, enable_dst: bool) -> anyhow::Result<Self> {
        let src_proxy = if enable_src {
            Some(Arc::new(KcpProxySrc::new(context.clone()).await?))
        } else {
            None
        };

        let dst_proxy = if enable_dst {
            let dst = KcpProxyDst::new(context.clone()).await?;
            dst.start().await;
            Some(Arc::new(dst))
        } else {
            None
        };

        Ok(Self {
            src_proxy,
            dst_proxy,
            enabled: enable_src || enable_dst,
        })
    }

    /// Check if this is a KCP packet and process it
    pub async fn try_process_packet(&self, data: &[u8], route_key: RouteKey) -> bool {
        if !self.enabled || data.len() < 13 {
            return false;
        }

        // Check if this is an OtherTurn packet with KCP type
        if let Ok(net_packet) = NetPacket::new(data) {
            if net_packet.protocol() != crate::protocol::Protocol::OtherTurn {
                return false;
            }

            let transport_protocol = net_packet.transport_protocol();
            let payload = net_packet.payload();

            match KcpPacketType::from(transport_protocol) {
                KcpPacketType::KcpSrc => {
                    // This is a source packet, process on destination side
                    if let Some(ref dst) = self.dst_proxy {
                        return dst.process_kcp_packet(&payload[1..], route_key).await;
                    }
                }
                KcpPacketType::KcpDst => {
                    // This is a destination packet, process on source side
                    if let Some(ref src) = self.src_proxy {
                        return src.process_kcp_packet(&payload[1..], route_key).await;
                    }
                }
            }
        }

        false
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl ProxyHandler for KcpProxy {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool> {
        // KCP proxy handles TCP packets that should go through KCP tunnel
        // This is called for packets coming from the TUN device
        
        if !self.enabled {
            return Ok(false);
        }

        // For now, we don't intercept packets here
        // The actual KCP proxying happens at a higher level
        Ok(false)
    }

    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        // Handle packets being sent back through the TUN device
        Ok(())
    }
}
