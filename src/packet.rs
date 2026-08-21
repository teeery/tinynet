use crate::address::{Ipv4Addr, MacAddr};
use crate::icmp::IcmpPacket;
use crate::tcp::TcpSegment;
use crate::udp::UdpDatagram;

// ========== ARP 报文 ==========
pub struct ArpPacket {
    pub request: bool, // true=请求, false=响应
    pub sender_ip: Ipv4Addr,
    pub sender_mac: MacAddr,
    pub target_ip: Ipv4Addr,
    pub target_mac: Option<MacAddr>, // 请求时 None,响应时 Some(回应者的 MAC)
}

// ========== 三层：IP 载荷 ==========
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpPayload {
    // 暂时保留文本载荷，让 v0.1-v0.5 的旧 demo 在重构期间继续工作。
    // 完成 v0.6 后，上层协议会逐步替代这个兼容分支。
    Data(String),
    Icmp(IcmpPacket),
    Udp(UdpDatagram),
    Tcp(TcpSegment),
}

// ========== 三层:IP 包 ==========
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpPacket {
    pub src: Ipv4Addr,      // 源 IP
    pub dst: Ipv4Addr,      // 目的 IP
    pub ttl: u8,            // 生存时间:每经过一个路由器减 1,减到 0 丢弃(防环)
    pub payload: IpPayload, // 上层协议载荷；IP 层不解释 ICMP 的具体语义
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
