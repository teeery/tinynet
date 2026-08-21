use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;

use crate::address::{network_address, same_subnet, Ipv4Addr, MacAddr};
use crate::icmp::{IcmpMessage, IcmpPacket};
use crate::packet::{ArpPacket, EthernetFrame, EthernetPayload, IpPacket, IpPayload};
use crate::routing::RoutingTable;
use crate::switch::Switch;

// ========== 主机 ==========
pub struct Host {
    name: String,                                   // 主机名
    ip: Ipv4Addr,                                   // IP 地址
    netmask: Ipv4Addr,                              // 子网掩码
    pub routing_table: RoutingTable,                // 路由表
    pub mac: MacAddr,                               // MAC 地址
    arp_cache: RefCell<HashMap<Ipv4Addr, MacAddr>>, // ARP 缓存:IP -> MAC
}

// Switch 收到主机的处理结果后，决定是直接转发二层帧，还是让主机把一个新的
// IP 包重新走 send_ip。后者保证 ICMP Reply 不会绕过路由和 ARP。
pub enum HostAction {
    SendEthernet(EthernetFrame),
    SendIp(IpPacket),
}

// send_ip 的调用者可以区分“没有路由”和“ARP 解析失败”，而不是只能看日志。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendError {
    NoRoute { destination: Ipv4Addr },
    ArpResolutionFailed { next_hop: Ipv4Addr },
}

impl fmt::Display for SendError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SendError::NoRoute { destination } => {
                write!(formatter, "没有到 {} 的路由", destination.to_dotted())
            }
            SendError::ArpResolutionFailed { next_hop } => {
                write!(formatter, "无法解析下一跳 {} 的 MAC", next_hop.to_dotted())
            }
        }
    }
}

impl std::error::Error for SendError {}

impl Host {
    pub fn new(
        name: &str,
        ip: Ipv4Addr,
        netmask: Ipv4Addr,
        routing_table: RoutingTable,
        mac: MacAddr,
    ) -> Self {
        Host {
            name: name.to_string(),
            ip,
            netmask,
            routing_table,
            mac,
            arp_cache: RefCell::new(HashMap::new()),
        }
    }

    // 旧的文本发送 API 现在只负责构造应用数据，所有网络层工作统一交给 send_ip。
    pub fn send_to(&self, dst_ip: Ipv4Addr, data: &str, switch: &mut Switch) {
        println!("[{}] 准备发送数据到 {}", self.name, dst_ip.to_dotted());

        let packet = IpPacket {
            src: self.ip,
            dst: dst_ip,
            ttl: 64,
            payload: IpPayload::Data(data.to_string()),
        };
        if let Err(error) = self.send_ip(packet, switch) {
            println!("[{}] {},发送失败", self.name, error);
        }
    }

    // ping 只表达“向目标发送 ICMP Echo Request”，不接触 MAC、ARP 或路由细节。
    pub fn ping(
        &self,
        destination: Ipv4Addr,
        sequence: u16,
        switch: &mut Switch,
    ) -> Result<(), SendError> {
        let packet = self.create_ping_packet(destination, sequence);
        println!(
            "[{} / ping] 创建 Echo Request: dst={}, id=1, seq={}",
            self.name,
            destination.to_dotted(),
            sequence
        );
        self.send_ip(packet, switch)
    }

    // 单独保留构造函数，便于测试“ping 产生了什么”，而不必启动整个网络。
    pub fn create_ping_packet(&self, destination: Ipv4Addr, sequence: u16) -> IpPacket {
        IpPacket {
            src: self.ip,
            dst: destination,
            ttl: 64,
            payload: IpPayload::Icmp(IcmpPacket::echo_request(1, sequence, b"tinynet".to_vec())),
        }
    }

    // 所有上层协议共用的 IP 发送路径：
    // packet.dst → 路由表 → 下一跳 IP → ARP → EthernetFrame → Switch。
    // 它完全不关心 payload 是文本、ICMP，还是未来接入的 TCP/UDP。
    pub fn send_ip(&self, packet: IpPacket, switch: &mut Switch) -> Result<(), SendError> {
        let destination = packet.dst;

        // 路由决策只回答“下一跳是谁”。直连路由的下一跳就是最终目的地址。
        // IP 决定最终目的地;路由决定下一跳;ARP 只负责解析下一跳。
        let next_hop_ip = self
            .next_hop(destination)
            .ok_or(SendError::NoRoute { destination })?;
        println!(
            "[{} / IP] 目的 {} → 下一跳 {}",
            self.name,
            destination.to_dotted(),
            next_hop_ip.to_dotted()
        );

        let destination_mac = self.resolve_arp(next_hop_ip, switch)?;
        let frame = EthernetFrame {
            src: self.mac,
            dst: destination_mac,
            payload: EthernetPayload::Ip(packet),
        };
        switch.forward(frame);
        Ok(())
    }

    // ARP 是独立的“下一跳 IP → MAC”步骤。缓存命中时不会再次广播。
    fn resolve_arp(
        &self,
        next_hop_ip: Ipv4Addr,
        switch: &mut Switch,
    ) -> Result<MacAddr, SendError> {
        // 缓存未命中 → 广播 ARP 请求(解析的是下一跳,不是目的地址)
        let cached = self.arp_cache.borrow().get(&next_hop_ip).copied();
        if cached.is_none() {
            println!("[{}] ARP 缓存未命中,广播 ARP 请求", self.name);
            let req = EthernetFrame {
                src: self.mac,
                dst: MacAddr::broadcast(),
                payload: EthernetPayload::Arp(ArpPacket {
                    request: true,
                    sender_ip: self.ip,
                    sender_mac: self.mac,
                    target_ip: next_hop_ip,
                    target_mac: None,
                }),
            };
            // 同步递归:请求广播出去 → 目标回响应 → 本机缓存被回填
            switch.forward(req);
        }

        // ARP 请求是同步模拟的：请求广播 → 目标响应 → 本机缓存更新，然后再读缓存。
        self.arp_cache
            .borrow()
            .get(&next_hop_ip)
            .copied()
            .ok_or(SendError::ArpResolutionFailed {
                next_hop: next_hop_ip,
            })
    }

    // 收到帧后的处理;若需要回应(如 ARP 响应),返回要回发的帧
    pub fn receive(&self, frame: &EthernetFrame) -> Option<HostAction> {
        match &frame.payload {
            EthernetPayload::Arp(arp) => {
                if arp.request && arp.target_ip == self.ip {
                    // 有人问我的 IP,回应自己的 MAC
                    println!(
                        "[{}] 收到 ARP 请求,回应自己的 MAC {}",
                        self.name,
                        self.mac.to_string()
                    );
                    Some(HostAction::SendEthernet(self.arp_reply(arp)))
                } else if !arp.request
                    && arp.target_ip == self.ip
                    && arp.target_mac == Some(self.mac)
                {
                    // 收到 ARP 响应,校验目标 MAC 确实是回给我的,缓存对方 IP -> MAC
                    self.arp_cache
                        .borrow_mut()
                        .insert(arp.sender_ip, arp.sender_mac);
                    println!(
                        "[{}] 学到 ARP: {} -> {}",
                        self.name,
                        arp.sender_ip.to_dotted(),
                        arp.sender_mac.to_string()
                    );
                    None
                } else {
                    None // 不是问我的,忽略
                }
            }
            EthernetPayload::Ip(pkt) => {
                if pkt.dst == self.ip {
                    match &pkt.payload {
                        IpPayload::Data(data) => println!(
                            "[{}] 收到来自 {} 的数据: {} (TTL={})",
                            self.name,
                            pkt.src.to_dotted(),
                            data,
                            pkt.ttl
                        ),
                        IpPayload::Icmp(_) => {
                            return self.receive_ip(pkt).map(HostAction::SendIp);
                        }
                        IpPayload::Udp(datagram) => println!(
                            "[{}] 收到 UDP 数据报: {} -> {} (TTL={})",
                            self.name, datagram.src_port, datagram.dst_port, pkt.ttl
                        ),
                        IpPayload::Tcp(segment) => println!(
                            "[{}] 收到 TCP 报文段: {} -> {}, seq={} (TTL={})",
                            self.name, segment.src_port, segment.dst_port, segment.seq, pkt.ttl
                        ),
                    }
                }
                None
            }
        }
    }

    // IP 接收层只处理“确实发给本机”的包，并把上层载荷分派给对应协议。
    // 若上层协议产生回复，这里只返回新的 IpPacket，不做任何二层封装。
    pub fn receive_ip(&self, packet: &IpPacket) -> Option<IpPacket> {
        if packet.dst != self.ip {
            return None;
        }
        match &packet.payload {
            IpPayload::Icmp(icmp) => self.handle_icmp(packet.src, icmp),
            IpPayload::Data(_) | IpPayload::Udp(_) | IpPayload::Tcp(_) => None,
        }
    }

    fn handle_icmp(&self, source: Ipv4Addr, packet: &IcmpPacket) -> Option<IpPacket> {
        match &packet.message {
            IcmpMessage::EchoRequest {
                identifier,
                sequence,
                data,
            } => {
                println!(
                    "[{} / ICMP] 收到 Echo Request: from={}, id={}, seq={}；创建 Echo Reply",
                    self.name,
                    source.to_dotted(),
                    identifier,
                    sequence
                );
                Some(IpPacket {
                    src: self.ip,
                    dst: source,
                    ttl: 64,
                    payload: IpPayload::Icmp(IcmpPacket::echo_reply(
                        *identifier,
                        *sequence,
                        data.clone(),
                    )),
                })
            }
            IcmpMessage::EchoReply {
                identifier,
                sequence,
                data,
            } => {
                println!(
                    "[{} / ping] reply from {}: id={}, seq={}, bytes={}",
                    self.name,
                    source.to_dotted(),
                    identifier,
                    sequence,
                    data.len()
                );
                None
            }
            IcmpMessage::TimeExceeded {
                original_src: _,
                original_dst,
            } => {
                println!(
                    "[{} / ICMP] 来自 {} 的 Time Exceeded，原目标={}",
                    self.name,
                    source.to_dotted(),
                    original_dst.to_dotted()
                );
                None
            }
            IcmpMessage::DestinationUnreachable {
                original_src: _,
                original_dst,
            } => {
                println!(
                    "[{} / ICMP] 来自 {} 的 Destination Unreachable，原目标={}",
                    self.name,
                    source.to_dotted(),
                    original_dst.to_dotted()
                );
                None
            }
        }
    }

    // 构造 ARP 响应(单播回给请求方)
    fn arp_reply(&self, req: &ArpPacket) -> EthernetFrame {
        EthernetFrame {
            src: self.mac,
            dst: req.sender_mac,
            payload: EthernetPayload::Arp(ArpPacket {
                request: false,
                sender_ip: self.ip,
                sender_mac: self.mac,
                target_ip: req.sender_ip,
                target_mac: Some(req.sender_mac), // 响应的目标 MAC 是「请求方」的 MAC
            }),
        }
    }

    // 路由决策:查路由表返回下一跳 IP,查不到(不可达)返回 None
    pub fn next_hop(&self, dst_ip: Ipv4Addr) -> Option<Ipv4Addr> {
        match self.routing_table.lookup(dst_ip) {
            Some(route) => Some(route.next_hop.unwrap_or(dst_ip)), // None=直连 → 下一跳就是目的 IP 本身
            None => None,                                          // 没有匹配路由,目的不可达
        }
    }

    // v0.1 遗留:L3 路由决策演示(打印决策过程,供教学观察)
    pub fn explain_route(&self, dst_ip: Ipv4Addr) -> Option<Ipv4Addr> {
        let src_net = network_address(self.ip, self.netmask);
        let dst_net = network_address(dst_ip, self.netmask);
        let prefix = self.netmask.prefix_len();

        let same = same_subnet(self.ip, dst_ip, self.netmask);
        let next_ip = self.next_hop(dst_ip);
        let next_str = match next_ip {
            Some(ip) => ip.to_dotted(),
            None => "不可达".to_string(),
        };
        let (decision, delivery) = if same {
            ("同一子网", "直接交付")
        } else {
            ("不同子网", "间接交付")
        };

        println!(
            r#"[{name}]
            准备发送数据包

            源地址:
            {src}/{prefix}

            目的地址:
            {dst}

            [IP 层]
            源网络:
            {src_net}/{prefix}

            目的网络:
            {dst_net}/{prefix}

            [路由决策]
            {decision}
            {delivery}

            下一跳:
            {next}"#,
            name = self.name,
            src = self.ip.to_dotted(),
            dst = dst_ip.to_dotted(),
            src_net = src_net.to_dotted(),
            dst_net = dst_net.to_dotted(),
            prefix = prefix,
            decision = decision,
            delivery = delivery,
            next = next_str,
        );

        next_ip
    }
}

#[cfg(test)]
mod tests {
    use std::rc::Rc;

    use super::*;

    fn direct_host(name: &str, ip: u32, mac_tail: u8) -> Rc<Host> {
        let ip = Ipv4Addr { value: ip };
        let netmask = Ipv4Addr { value: 0xFFFF_FF00 };
        let mut routes = RoutingTable::new();
        routes.add_direct_route(0, ip, netmask);
        Rc::new(Host::new(
            name,
            ip,
            netmask,
            routes,
            MacAddr::new([0x02, 0, 0, 0, 0, mac_tail]),
        ))
    }

    #[test]
    fn send_ip_uses_route_then_arp_and_caches_the_result() {
        let alice = direct_host("Alice", 0xC0A8_0102, 2);
        let bob = direct_host("Bob", 0xC0A8_0103, 3);
        let mut switch = Switch::new();
        switch.connect(0, alice.clone());
        switch.connect(1, bob.clone());

        let packet = IpPacket {
            src: alice.ip,
            dst: bob.ip,
            ttl: 64,
            payload: IpPayload::Data("hello".to_string()),
        };
        assert_eq!(alice.send_ip(packet, &mut switch), Ok(()));
        assert_eq!(alice.arp_cache.borrow().get(&bob.ip), Some(&bob.mac));
    }

    #[test]
    fn send_ip_returns_no_route_without_touching_ethernet() {
        let ip = Ipv4Addr { value: 0xC0A8_0102 };
        let host = Host::new(
            "isolated",
            ip,
            Ipv4Addr { value: 0xFFFF_FF00 },
            RoutingTable::new(),
            MacAddr::new([0x02, 0, 0, 0, 0, 2]),
        );
        let packet = IpPacket {
            src: ip,
            dst: Ipv4Addr { value: 0x0A00_0002 },
            ttl: 64,
            payload: IpPayload::Data("unreachable".to_string()),
        };

        assert_eq!(
            host.send_ip(packet, &mut Switch::new()),
            Err(SendError::NoRoute {
                destination: Ipv4Addr { value: 0x0A00_0002 },
            })
        );
    }

    #[test]
    fn echo_request_is_turned_into_a_matching_echo_reply() {
        let alice = direct_host("Alice", 0xC0A8_0102, 2);
        let bob = direct_host("Bob", 0xC0A8_0103, 3);
        let request = alice.create_ping_packet(bob.ip, 9);
        let reply = bob.receive_ip(&request).unwrap();

        assert_eq!(reply.src, bob.ip);
        assert_eq!(reply.dst, alice.ip);
        assert_eq!(reply.ttl, 64);
        assert_eq!(
            reply.payload,
            IpPayload::Icmp(IcmpPacket::echo_reply(1, 9, b"tinynet".to_vec()))
        );
    }
}
