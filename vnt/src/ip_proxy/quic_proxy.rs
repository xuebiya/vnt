//! QUIC Proxy Module for VNT
//!
//! This module provides QUIC-based TCP proxy functionality,
//! ported from EasyTier's quic_proxy implementation.
//!
//! QUIC provides secure, multiplexed connections with built-in
//! encryption and congestion control.

use std::io::{self, IoSliceMut};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::Mutex;
use quinn::crypto::rustls::QuicClientConfig;
use quinn::udp::RecvMeta;
use quinn::{
    congestion::BbrConfig, AsyncUdpSocket, ClientConfig, Connection, Endpoint, EndpointConfig,
    Incoming, ServerConfig, TransportConfig, UdpPoller,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use tokio::io::{copy_bidirectional, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpSocket;
use tokio::task::JoinSet;
use tokio::time::timeout;

use crate::channel::context::ChannelContext;
use crate::ip_proxy::ProxyHandler;
use packet::ip::ipv4::packet::IpV4Packet;

/// QUIC connection data for proxy
#[derive(Clone, Debug)]
pub struct QuicProxyInfo {
    pub dst_addr: SocketAddr,
}

impl QuicProxyInfo {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(7);
        match self.dst_addr {
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
        if buf.len() < 7 {
            return None;
        }
        let dst_addr = if buf[0] == 4 {
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            SocketAddr::V4(SocketAddrV4::new(ip, port))
        } else {
            return None; // Only IPv4 supported for now
        };
        Some(QuicProxyInfo { dst_addr })
    }
}

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE: This is insecure and should only be used for internal VPN tunnels.
#[derive(Debug)]
struct SkipServerVerification(Arc<rustls::crypto::CryptoProvider>);

impl SkipServerVerification {
    fn new(provider: Arc<rustls::crypto::CryptoProvider>) -> Arc<Self> {
        Arc::new(Self(provider))
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Initialize the crypto provider for rustls
fn init_crypto_provider() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

/// Get insecure TLS client config (for internal VPN use)
fn get_insecure_tls_client_config() -> rustls::ClientConfig {
    init_crypto_provider();
    let provider = rustls::crypto::CryptoProvider::get_default().unwrap();
    let mut config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(SkipServerVerification::new(provider.clone()))
        .with_no_client_auth();
    config.enable_sni = true;
    config.enable_early_data = false;
    config
}

/// Get insecure TLS certificate for server
fn get_insecure_tls_cert<'a>() -> (Vec<CertificateDer<'a>>, PrivateKeyDer<'a>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let priv_key = cert.serialize_private_key_der();
    let priv_key = rustls::pki_types::PrivatePkcs8KeyDer::from(priv_key);
    let cert_chain = vec![cert_der.clone().into()];
    (cert_chain, priv_key.into())
}

/// Configure QUIC client with BBR congestion control
fn configure_client() -> ClientConfig {
    let client_crypto = QuicClientConfig::try_from(get_insecure_tls_client_config()).unwrap();
    let mut client_config = ClientConfig::new(Arc::new(client_crypto));

    let mut transport_config = TransportConfig::default();
    transport_config.congestion_controller_factory(Arc::new(BbrConfig::default()));
    transport_config.keep_alive_interval(Some(Duration::from_secs(5)));
    client_config.transport_config(Arc::new(transport_config));

    client_config
}

/// Configure QUIC server
fn configure_server() -> Result<(ServerConfig, Vec<u8>), Box<dyn std::error::Error>> {
    let (certs, key) = get_insecure_tls_cert();

    let mut server_config = ServerConfig::with_single_cert(certs.clone(), key)?;
    let transport_config = Arc::get_mut(&mut server_config.transport).unwrap();
    transport_config.max_concurrent_uni_streams(10_u8.into());
    transport_config.max_concurrent_bidi_streams(10_u8.into());
    transport_config.congestion_controller_factory(Arc::new(BbrConfig::default()));

    Ok((server_config, certs[0].to_vec()))
}

/// Wrapper for QUIC UDP socket without GRO
#[derive(Clone, Debug)]
struct NoGroAsyncUdpSocket {
    inner: Arc<dyn AsyncUdpSocket>,
}

impl AsyncUdpSocket for NoGroAsyncUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        self.inner.clone().create_io_poller()
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit) -> std::io::Result<()> {
        self.inner.try_send(transmit)
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<std::io::Result<usize>> {
        self.inner.poll_recv(cx, bufs, meta)
    }

    fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn may_fragment(&self) -> bool {
        self.inner.may_fragment()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// Setup socket2 socket with proper options
fn setup_socket2(socket: &socket2::Socket, bind_addr: &SocketAddr) -> io::Result<()> {
    socket.set_reuse_address(true)?;
    #[cfg(not(windows))]
    socket.set_reuse_port(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&(*bind_addr).into())?;
    Ok(())
}

/// Create a QUIC server endpoint
fn make_server_endpoint(bind_addr: SocketAddr) -> Result<(Endpoint, Vec<u8>), Box<dyn std::error::Error>> {
    let (server_config, server_cert) = configure_server()?;

    let socket2_socket = socket2::Socket::new(
        socket2::Domain::for_address(bind_addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    setup_socket2(&socket2_socket, &bind_addr)?;
    let socket = std::net::UdpSocket::from(socket2_socket);

    let runtime =
        quinn::default_runtime().ok_or_else(|| std::io::Error::other("no async runtime found"))?;
    let mut endpoint_config = EndpointConfig::default();
    endpoint_config.max_udp_payload_size(1200)?;
    let socket: NoGroAsyncUdpSocket = NoGroAsyncUdpSocket {
        inner: runtime.wrap_udp_socket(socket)?,
    };
    let endpoint = Endpoint::new_with_abstract_socket(
        endpoint_config,
        Some(server_config),
        Arc::new(socket),
        runtime,
    )?;
    Ok((endpoint, server_cert))
}

/// QUIC Stream wrapper for async read/write
pub struct QuicStream {
    endpoint: Option<Endpoint>,
    connection: Option<Connection>,
    sender: quinn::SendStream,
    receiver: quinn::RecvStream,
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.receiver).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        AsyncWrite::poll_write(Pin::new(&mut this.sender), cx, buf)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.sender).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.sender).poll_shutdown(cx)
    }
}

/// NAT entry for QUIC proxy connections
#[derive(Debug)]
struct QuicNatEntry {
    src: SocketAddr,
    dst: SocketAddr,
    start_time: std::time::Instant,
}

/// QUIC Proxy Source - initiates QUIC connections to peers
pub struct QuicProxySrc {
    context: ChannelContext,
    nat_map: Arc<DashMap<SocketAddrV4, QuicNatEntry>>,
    tasks: Arc<Mutex<JoinSet<()>>>,
}

impl QuicProxySrc {
    pub async fn new(context: ChannelContext) -> anyhow::Result<Self> {
        let nat_map = Arc::new(DashMap::new());
        let tasks = Arc::new(Mutex::new(JoinSet::new()));

        Ok(Self {
            context,
            nat_map,
            tasks,
        })
    }

    /// Connect to a peer via QUIC
    pub async fn connect(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        quic_port: u16,
    ) -> anyhow::Result<QuicStream> {
        let SocketAddr::V4(dst_v4) = dst else {
            return Err(anyhow::anyhow!("Only IPv4 destinations supported"));
        };

        let mut endpoint = Endpoint::client("0.0.0.0:0".parse().unwrap())?;
        endpoint.set_default_client_config(configure_client());

        let connection = endpoint
            .connect(
                SocketAddr::new((*dst_v4.ip()).into(), quic_port),
                "localhost",
            )
            .unwrap()
            .await?;

        let (mut sender, receiver) = connection.open_bi().await?;

        // Send proxy destination info
        let proxy_info = QuicProxyInfo { dst_addr: dst };
        let info_buf = proxy_info.encode();
        sender.write_all(&[info_buf.len() as u8]).await?;
        sender.write_all(&info_buf).await?;

        Ok(QuicStream {
            endpoint: Some(endpoint),
            connection: Some(connection),
            sender,
            receiver,
        })
    }
}

/// QUIC Proxy Destination - accepts QUIC connections from peers
pub struct QuicProxyDst {
    endpoint: Arc<Endpoint>,
    proxy_entries: Arc<DashMap<SocketAddr, QuicNatEntry>>,
    tasks: Arc<Mutex<JoinSet<()>>>,
    local_port: u16,
}

impl QuicProxyDst {
    pub fn new(listen_port: u16) -> anyhow::Result<Self> {
        let bind_addr: SocketAddr = format!("0.0.0.0:{}", listen_port).parse().unwrap();
        let (endpoint, _) = make_server_endpoint(bind_addr)
            .map_err(|e| anyhow::anyhow!("Failed to create QUIC endpoint: {}", e))?;

        let local_port = endpoint.local_addr()?.port();

        Ok(Self {
            endpoint: Arc::new(endpoint),
            proxy_entries: Arc::new(DashMap::new()),
            tasks: Arc::new(Mutex::new(JoinSet::new())),
            local_port,
        })
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Start accepting QUIC connections
    pub async fn start(&self) -> anyhow::Result<()> {
        let endpoint = self.endpoint.clone();
        let proxy_entries = self.proxy_entries.clone();

        self.tasks.lock().spawn(async move {
            loop {
                match endpoint.accept().await {
                    Some(incoming) => {
                        let proxy_entries_clone = proxy_entries.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                Self::handle_connection(incoming, proxy_entries_clone).await
                            {
                                log::error!("QUIC connection error: {:?}", e);
                            }
                        });
                    }
                    None => {
                        log::info!("QUIC endpoint closed");
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn handle_connection(
        incoming: Incoming,
        proxy_entries: Arc<DashMap<SocketAddr, QuicNatEntry>>,
    ) -> anyhow::Result<()> {
        let remote_addr = incoming.remote_address();
        let conn = incoming.await?;

        log::info!("Accepted QUIC connection from {}", remote_addr);

        let (sender, mut receiver) = conn.accept_bi().await?;

        // Read proxy destination info
        let len = receiver.read_u8().await?;
        let mut buf = vec![0u8; len as usize];
        receiver.read_exact(&mut buf).await?;

        let proxy_info = QuicProxyInfo::decode(&buf)
            .ok_or_else(|| anyhow::anyhow!("Failed to decode proxy info"))?;

        proxy_entries.insert(
            remote_addr,
            QuicNatEntry {
                src: remote_addr,
                dst: proxy_info.dst_addr,
                start_time: std::time::Instant::now(),
            },
        );

        // Connect to actual destination
        let socket = TcpSocket::new_v4()?;
        let mut dst_stream = timeout(Duration::from_secs(10), socket.connect(proxy_info.dst_addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        let mut quic_stream = QuicStream {
            endpoint: None,
            connection: Some(conn),
            sender,
            receiver,
        };

        // Proxy data bidirectionally
        if let Err(e) = copy_bidirectional(&mut quic_stream, &mut dst_stream).await {
            log::debug!("QUIC proxy connection closed: {:?}", e);
        }

        // Cleanup
        proxy_entries.remove(&remote_addr);

        Ok(())
    }
}

/// Combined QUIC Proxy that handles both source and destination
#[derive(Clone)]
pub struct QuicProxy {
    src_proxy: Option<Arc<QuicProxySrc>>,
    dst_proxy: Option<Arc<QuicProxyDst>>,
    enabled: bool,
    local_port: u16,
}

impl QuicProxy {
    pub async fn new(
        context: ChannelContext,
        enable_src: bool,
        enable_dst: bool,
        listen_port: u16,
    ) -> anyhow::Result<Self> {
        let src_proxy = if enable_src {
            Some(Arc::new(QuicProxySrc::new(context.clone()).await?))
        } else {
            None
        };

        let (dst_proxy, local_port) = if enable_dst {
            let dst = QuicProxyDst::new(listen_port)?;
            let port = dst.local_port();
            dst.start().await?;
            (Some(Arc::new(dst)), port)
        } else {
            (None, 0)
        };

        Ok(Self {
            src_proxy,
            dst_proxy,
            enabled: enable_src || enable_dst,
            local_port,
        })
    }

    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Connect to a destination through QUIC proxy
    pub async fn connect(
        &self,
        src: SocketAddr,
        dst: SocketAddr,
        quic_port: u16,
    ) -> anyhow::Result<QuicStream> {
        let src_proxy = self
            .src_proxy
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("QUIC source proxy not enabled"))?;

        src_proxy.connect(src, dst, quic_port).await
    }
}

impl ProxyHandler for QuicProxy {
    fn recv_handle(
        &self,
        ipv4: &mut IpV4Packet<&mut [u8]>,
        source: Ipv4Addr,
        destination: Ipv4Addr,
    ) -> io::Result<bool> {
        // QUIC proxy handles TCP packets that should go through QUIC tunnel
        // This is called for packets coming from the TUN device

        if !self.enabled {
            return Ok(false);
        }

        // For now, we don't intercept packets here
        // The actual QUIC proxying happens at a higher level
        Ok(false)
    }

    fn send_handle(&self, ipv4: &mut IpV4Packet<&mut [u8]>) -> io::Result<()> {
        // Handle packets being sent back through the TUN device
        Ok(())
    }
}
