use crate::dns::DnsMessage;

// ========== v0.7：UDP ==========
// UDP 只提供端口复用和无连接数据报，不维护 Seq、ACK、窗口或连接状态。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpDatagram {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: UdpPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UdpPayload {
    Dns(DnsMessage),
}
