use crate::address::{Ipv4Addr, MacAddr};

// ========== ARP 报文 ==========
pub struct ArpPacket {
    pub request: bool, // true=请求, false=响应
    pub sender_ip: Ipv4Addr,
    pub sender_mac: MacAddr,
    pub target_ip: Ipv4Addr,
    pub target_mac: Option<MacAddr>, // 请求时 None,响应时 Some(回应者的 MAC)
}

// ========== 三层:IP 包 ==========
pub struct IpPacket {
    pub src: Ipv4Addr, // 源 IP
    pub dst: Ipv4Addr, // 目的 IP
    pub ttl: u8,       // 生存时间:每经过一个路由器减 1,减到 0 丢弃(防环)
    pub payload: String,  // 载荷
}

// ========== 以太网帧 ==========
pub enum EthernetPayload {
    Arp(ArpPacket),
    Ip(IpPacket),
}

pub struct EthernetFrame {
    pub src: MacAddr,
    pub dst: MacAddr,
    pub payload: EthernetPayload,
}
