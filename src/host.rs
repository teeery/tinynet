use std::cell::RefCell;
use std::collections::HashMap;

use crate::address::{network_address, same_subnet, Ipv4Addr, MacAddr};
use crate::packet::{ArpPacket, EthernetFrame, EthernetPayload, IpPacket};
use crate::routing::RoutingTable;
use crate::switch::Switch;

// ========== 主机 ==========
pub struct Host {
    name: String,                                    // 主机名
    ip: Ipv4Addr,                                    // IP 地址
    netmask: Ipv4Addr,                               // 子网掩码
    pub routing_table: RoutingTable,                 // 路由表
    pub mac: MacAddr,                                // MAC 地址
    arp_cache: RefCell<HashMap<Ipv4Addr, MacAddr>>,  // ARP 缓存:IP -> MAC
}

impl Host {
    pub fn new(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr, routing_table: RoutingTable, mac: MacAddr) -> Self {
        Host {
            name: name.to_string(),
            ip,
            netmask,
            routing_table,
            mac,
            arp_cache: RefCell::new(HashMap::new()),
        }
    }

    // 发送数据:先解析目标 MAC(必要时广播 ARP 请求),再发数据帧
    pub fn send_to(&self, dst_ip: Ipv4Addr, data: &str, switch: &mut Switch) {
        println!("[{}] 准备发送数据到 {}", self.name, dst_ip.to_dotted());

        // 路由决策:查路由表确定下一跳
        // IP 决定最终目的地;路由决定下一跳;ARP 只负责解析下一跳。
        let next_hop_ip = match self.next_hop(dst_ip) {
            Some(ip) => ip,
            None => {
                println!("[{}] 没有到 {} 的路由,发送失败", self.name, dst_ip.to_dotted());
                return;
            }
        };

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

        // 重新读缓存(ARP 完成后应该有了)
        let dst_mac = self.arp_cache.borrow().get(&next_hop_ip).copied();
        match dst_mac {
            Some(mac) => {
                let frame = EthernetFrame {
                    src: self.mac,
                    dst: mac,
                    payload: EthernetPayload::Ip(IpPacket {
                        src: self.ip,
                        dst: dst_ip,
                        ttl: 64, // 发送方设定初始 TTL
                        payload: data.to_string(),
                    }),
                };
                switch.forward(frame);
            }
            None => {
                println!("[{}] 无法解析 {} 的 MAC,发送失败", self.name, next_hop_ip.to_dotted());
            }
        }
    }

    // 收到帧后的处理;若需要回应(如 ARP 响应),返回要回发的帧
    pub fn receive(&self, frame: &EthernetFrame) -> Option<EthernetFrame> {
        match &frame.payload {
            EthernetPayload::Arp(arp) => {
                if arp.request && arp.target_ip == self.ip {
                    // 有人问我的 IP,回应自己的 MAC
                    println!("[{}] 收到 ARP 请求,回应自己的 MAC {}", self.name, self.mac.to_string());
                    Some(self.arp_reply(arp))
                } else if !arp.request && arp.target_ip == self.ip && arp.target_mac == Some(self.mac) {
                    // 收到 ARP 响应,校验目标 MAC 确实是回给我的,缓存对方 IP -> MAC
                    self.arp_cache.borrow_mut().insert(arp.sender_ip, arp.sender_mac);
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
                    println!("[{}] 收到来自 {} 的数据: {} (TTL={})", self.name, pkt.src.to_dotted(), pkt.payload, pkt.ttl);
                }
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
            None => None, // 没有匹配路由,目的不可达
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
