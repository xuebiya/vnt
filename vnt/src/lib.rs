pub const VNT_VERSION: &'static str = env!("CARGO_PKG_VERSION");

pub mod channel;
pub mod cipher;
pub mod core;
mod external_route;
pub mod handle;
#[cfg(feature = "ip_proxy")]
pub mod ip_proxy;
pub mod nat;
#[cfg(feature = "port_mapping")]
mod port_mapping;
mod proto;
pub mod protocol;
mod tun_tap_device;
pub use tun_tap_device::*;
pub mod util;

pub use handle::callback::*;

pub mod compression;
pub use packet;

// Re-export KCP proxy types when feature is enabled
#[cfg(all(feature = "ip_proxy", feature = "kcp_proxy"))]
pub use ip_proxy::kcp_proxy::{KcpProxy, KcpProxyDst, KcpProxySrc};

// Re-export QUIC proxy types when feature is enabled
#[cfg(all(feature = "ip_proxy", feature = "quic_proxy"))]
pub use ip_proxy::quic_proxy::{QuicProxy, QuicProxyDst, QuicProxySrc};

// Re-export proxy configuration
#[cfg(feature = "ip_proxy")]
pub use ip_proxy::{init_proxy_with_config, ProxyConfig};

pub(crate) fn ignore_io_interrupted(e: std::io::Error) -> std::io::Result<()> {
    if e.kind() == std::io::ErrorKind::Interrupted {
        log::warn!("ignore_io_interrupted");
        Ok(())
    } else {
        Err(e)
    }
}
