#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Protocol {
    /// Punch through NAT
    Punch,
    /// KCP proxy packet from source side
    #[cfg(feature = "kcp_proxy")]
    KcpSrc,
    /// KCP proxy packet from destination side
    #[cfg(feature = "kcp_proxy")]
    KcpDst,
    /// QUIC proxy control packet
    #[cfg(feature = "quic_proxy")]
    QuicProxy,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            1 => Protocol::Punch,
            #[cfg(feature = "kcp_proxy")]
            0x10 => Protocol::KcpSrc,
            #[cfg(feature = "kcp_proxy")]
            0x11 => Protocol::KcpDst,
            #[cfg(feature = "quic_proxy")]
            0x20 => Protocol::QuicProxy,
            val => Protocol::Unknown(val),
        }
    }
}

impl Into<u8> for Protocol {
    fn into(self) -> u8 {
        match self {
            Protocol::Punch => 1,
            #[cfg(feature = "kcp_proxy")]
            Protocol::KcpSrc => 0x10,
            #[cfg(feature = "kcp_proxy")]
            Protocol::KcpDst => 0x11,
            #[cfg(feature = "quic_proxy")]
            Protocol::QuicProxy => 0x20,
            Protocol::Unknown(val) => val,
        }
    }
}
