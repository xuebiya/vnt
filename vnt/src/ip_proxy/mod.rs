use std::net::Ipv4Addr;
use std::sync::Arc;
use std::{io, thread};

use crossbeam_utils::atomic::AtomicCell;

use packet::ip::ipv4;
use packet::ip::ipv4::packet::IpV4Packet;

use crate::channel::context::ChannelContext;
use crate::cipher::Cipher;
use crate::handle::CurrentDeviceInfo;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
use crate::ip_proxy::icmp_proxy::IcmpProxy;
use crate::ip_proxy::tcp_proxy::TcpProxy;
use crate::ip_proxy::udp_proxy::UdpProxy;
use crate::util::StopManager;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub mod icmp_proxy;
pub mod tcp_proxy;
pub mod udp_proxy;

// KCP proxy module - provides reliable UDP transport
#[cfg(feature = "kcp_proxy")]
pub mod kcp_proxy;

// QUIC proxy module - provides QUIC-based transport
#[cfg(feature = "quic_proxy")]
pub mod quic_proxy;

pub trait ProxyHandler {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool>;
    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()>;
}

/// Configuration for KCP/QUIC proxy features
#[derive(Clone, Debug, Default)]
pub struct ProxyConfig {
    /// Enable KCP proxy source (outgoing connections)
    #[cfg(feature = "kcp_proxy")]
    pub enable_kcp_src: bool,
    /// Enable KCP proxy destination (incoming connections)
    #[cfg(feature = "kcp_proxy")]
    pub enable_kcp_dst: bool,
    /// Enable QUIC proxy source (outgoing connections)
    #[cfg(feature = "quic_proxy")]
    pub enable_quic_src: bool,
    /// Enable QUIC proxy destination (incoming connections)
    #[cfg(feature = "quic_proxy")]
    pub enable_quic_dst: bool,
    /// QUIC listen port (0 for auto-assign)
    #[cfg(feature = "quic_proxy")]
    pub quic_listen_port: u16,
}

#[derive(Clone)]
pub struct IpProxyMap {
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    icmp_proxy: IcmpProxy,
    tcp_proxy: TcpProxy,
    udp_proxy: UdpProxy,
    #[cfg(feature = "kcp_proxy")]
    kcp_proxy: Option<kcp_proxy::KcpProxy>,
    #[cfg(feature = "quic_proxy")]
    quic_proxy: Option<quic_proxy::QuicProxy>,
}

pub fn init_proxy(
    context: ChannelContext,
    stop_manager: StopManager,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
) -> anyhow::Result<IpProxyMap> {
    init_proxy_with_config(
        context,
        stop_manager,
        current_device,
        client_cipher,
        ProxyConfig::default(),
    )
}

/// Initialize proxy with custom configuration for KCP/QUIC features
pub fn init_proxy_with_config(
    context: ChannelContext,
    stop_manager: StopManager,
    current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    client_cipher: Cipher,
    config: ProxyConfig,
) -> anyhow::Result<IpProxyMap> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ipProxy")
        .build()?;
    let proxy_map = runtime.block_on(init_proxy0(context, current_device, client_cipher, config))?;
    let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
    let worker = stop_manager.add_listener("ipProxy".into(), move || {
        let _ = sender.send(());
    })?;
    thread::Builder::new()
        .name("ipProxy".into())
        .spawn(move || {
            runtime.block_on(async {
                let _ = receiver.await;
            });
            runtime.shutdown_background();
            drop(worker);
        })?;

    return Ok(proxy_map);
}

async fn init_proxy0(
    context: ChannelContext,
    _current_device: Arc<AtomicCell<CurrentDeviceInfo>>,
    _client_cipher: Cipher,
    _config: ProxyConfig,
) -> anyhow::Result<IpProxyMap> {
    let default_interface = context.default_interface().clone();
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    let icmp_proxy =
        IcmpProxy::new(context.clone(), _current_device, _client_cipher, &default_interface).await?;
    let tcp_proxy = TcpProxy::new(default_interface.clone()).await?;
    let udp_proxy = UdpProxy::new(default_interface.clone()).await?;

    // Initialize KCP proxy if enabled
    #[cfg(feature = "kcp_proxy")]
    let kcp_proxy = if _config.enable_kcp_src || _config.enable_kcp_dst {
        match kcp_proxy::KcpProxy::new(
            context.clone(),
            _config.enable_kcp_src,
            _config.enable_kcp_dst,
        )
        .await
        {
            Ok(proxy) => {
                log::info!(
                    "KCP proxy initialized (src: {}, dst: {})",
                    _config.enable_kcp_src,
                    _config.enable_kcp_dst
                );
                Some(proxy)
            }
            Err(e) => {
                log::warn!("Failed to initialize KCP proxy: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    // Initialize QUIC proxy if enabled
    #[cfg(feature = "quic_proxy")]
    let quic_proxy = if _config.enable_quic_src || _config.enable_quic_dst {
        match quic_proxy::QuicProxy::new(
            context.clone(),
            _config.enable_quic_src,
            _config.enable_quic_dst,
            _config.quic_listen_port,
        )
        .await
        {
            Ok(proxy) => {
                log::info!(
                    "QUIC proxy initialized (src: {}, dst: {}, port: {})",
                    _config.enable_quic_src,
                    _config.enable_quic_dst,
                    proxy.local_port()
                );
                Some(proxy)
            }
            Err(e) => {
                log::warn!("Failed to initialize QUIC proxy: {:?}", e);
                None
            }
        }
    } else {
        None
    };

    Ok(IpProxyMap {
        #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
        icmp_proxy,
        tcp_proxy,
        udp_proxy,
        #[cfg(feature = "kcp_proxy")]
        kcp_proxy,
        #[cfg(feature = "quic_proxy")]
        quic_proxy,
    })
}

impl IpProxyMap {
    /// Get reference to KCP proxy if enabled
    #[cfg(feature = "kcp_proxy")]
    pub fn kcp_proxy(&self) -> Option<&kcp_proxy::KcpProxy> {
        self.kcp_proxy.as_ref()
    }

    /// Get reference to QUIC proxy if enabled
    #[cfg(feature = "quic_proxy")]
    pub fn quic_proxy(&self) -> Option<&quic_proxy::QuicProxy> {
        self.quic_proxy.as_ref()
    }

    /// Check if KCP proxy is enabled and active
    #[cfg(feature = "kcp_proxy")]
    pub fn is_kcp_enabled(&self) -> bool {
        self.kcp_proxy.as_ref().map_or(false, |p| p.is_enabled())
    }

    /// Check if QUIC proxy is enabled and active
    #[cfg(feature = "quic_proxy")]
    pub fn is_quic_enabled(&self) -> bool {
        self.quic_proxy.as_ref().map_or(false, |p| p.is_enabled())
    }

    /// Get QUIC proxy local port if available
    #[cfg(feature = "quic_proxy")]
    pub fn quic_local_port(&self) -> Option<u16> {
        self.quic_proxy.as_ref().map(|p| p.local_port())
    }
}

impl ProxyHandler for IpProxyMap {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool> {
        match ipv4.protocol() {
            ipv4::protocol::Protocol::Tcp => self.tcp_proxy.recv_handle(ipv4, source, destination),
            ipv4::protocol::Protocol::Udp => self.udp_proxy.recv_handle(ipv4, source, destination),
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            ipv4::protocol::Protocol::Icmp => {
                self.icmp_proxy.recv_handle(ipv4, source, destination)
            }
            _ => {
                log::warn!(
                    "不支持的ip代理ipv4协议{:?}:{}->{}->{}",
                    ipv4.protocol(),
                    source,
                    destination,
                    ipv4.destination_ip()
                );
                Ok(false)
            }
        }
    }

    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        match ipv4.protocol() {
            ipv4::protocol::Protocol::Tcp => self.tcp_proxy.send_handle(ipv4),
            ipv4::protocol::Protocol::Udp => self.udp_proxy.send_handle(ipv4),
            #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
            ipv4::protocol::Protocol::Icmp => self.icmp_proxy.send_handle(ipv4),
            _ => Ok(()),
        }
    }
}
