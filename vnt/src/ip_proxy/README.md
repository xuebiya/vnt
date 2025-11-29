# VNT IP Proxy Module

This module provides IP-level proxy functionality for VNT, including TCP, UDP, ICMP, and the newly added KCP and QUIC proxy features.

## Features

### KCP Proxy (`kcp_proxy` feature)

KCP (KCP Protocol) provides reliable, ordered delivery over UDP with configurable parameters for latency vs bandwidth tradeoff. This is particularly useful for:

- Low-latency gaming traffic
- Real-time communication
- Unstable network conditions where TCP performs poorly

**Usage:**

```rust
use vnt::ip_proxy::{init_proxy_with_config, ProxyConfig};

let config = ProxyConfig {
    enable_kcp_src: true,  // Enable outgoing KCP connections
    enable_kcp_dst: true,  // Enable incoming KCP connections
    ..Default::default()
};

let proxy_map = init_proxy_with_config(
    context,
    stop_manager,
    current_device,
    client_cipher,
    config,
)?;
```

### QUIC Proxy (`quic_proxy` feature)

QUIC provides secure, multiplexed connections with built-in encryption and congestion control. Benefits include:

- Built-in TLS 1.3 encryption
- Multiplexed streams over single connection
- Better performance on lossy networks
- 0-RTT connection resumption

**Usage:**

```rust
use vnt::ip_proxy::{init_proxy_with_config, ProxyConfig};

let config = ProxyConfig {
    enable_quic_src: true,   // Enable outgoing QUIC connections
    enable_quic_dst: true,   // Enable incoming QUIC connections
    quic_listen_port: 0,     // 0 for auto-assign, or specify a port
    ..Default::default()
};

let proxy_map = init_proxy_with_config(
    context,
    stop_manager,
    current_device,
    client_cipher,
    config,
)?;

// Get the assigned QUIC port
if let Some(port) = proxy_map.quic_local_port() {
    println!("QUIC proxy listening on port {}", port);
}
```

## Cargo Features

Add the following to your `Cargo.toml`:

```toml
[dependencies]
vnt = { version = "1.2.16", features = ["kcp_proxy", "quic_proxy"] }
```

Or enable individual features:

```toml
# KCP only
vnt = { version = "1.2.16", features = ["kcp_proxy"] }

# QUIC only
vnt = { version = "1.2.16", features = ["quic_proxy"] }
```

## Architecture

### KCP Proxy

```
┌─────────────────┐     KCP over VNT     ┌─────────────────┐
│   KcpProxySrc   │ ◄──────────────────► │   KcpProxyDst   │
│  (Client Side)  │                      │  (Server Side)  │
└────────┬────────┘                      └────────┬────────┘
         │                                        │
         ▼                                        ▼
    TCP Traffic                              TCP Traffic
    (Application)                            (Destination)
```

### QUIC Proxy

```
┌─────────────────┐    QUIC Connection   ┌─────────────────┐
│  QuicProxySrc   │ ◄──────────────────► │  QuicProxyDst   │
│  (Client Side)  │                      │  (Server Side)  │
└────────┬────────┘                      └────────┬────────┘
         │                                        │
         ▼                                        ▼
    TCP Traffic                              TCP Traffic
    (Application)                            (Destination)
```

## Protocol Details

### KCP Packet Types

- `KcpSrc (0x10)`: Packets from source (client) side
- `KcpDst (0x11)`: Packets from destination (server) side

### QUIC Packet Types

- `QuicProxy (0x20)`: QUIC proxy control packets

## Credits

This implementation is ported from [EasyTier](https://github.com/EasyTier/EasyTier)'s KCP and QUIC proxy functionality.
