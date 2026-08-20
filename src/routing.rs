use crate::address::{network_address, prefix_to_mask, same_subnet, Ipv4Addr, MacAddr};
use crate::icmp::IcmpPacket;
use crate::packet::{IpPacket, IpPayload};

// ========== v0.3:路由表 ==========

// 一条路由条目
pub struct RouteEntry {
    pub network: Ipv4Addr,          // 目的网络地址
    pub prefix_len: u8,             // 前缀长度
    pub next_hop: Option<Ipv4Addr>, // None 表示直连,Some(IP) = 经过网关
    pub interface: usize,           // 出接口索引(指向 Router.interfaces)
}

impl RouteEntry {
    // 判断这条路由是否匹配目的 IP
    fn matches(&self, dst: Ipv4Addr) -> bool {
        let mask = prefix_to_mask(self.prefix_len);
        network_address(dst, mask).value == self.network.value
    }
}

// 路由表:一组路由 + 最长前缀匹配
pub struct RoutingTable {
    routes: Vec<RouteEntry>,
}

impl RoutingTable {
    pub fn new() -> Self {
        RoutingTable { routes: Vec::new() }
    }

    // 最长前缀匹配:所有匹配路由里,选 prefix_len 最长的那条
    pub fn lookup(&self, dst_ip: Ipv4Addr) -> Option<&RouteEntry> {
        self.routes
            .iter()
            .filter(|r| r.matches(dst_ip))
            .max_by_key(|r| r.prefix_len)
    }

    // 添加直连路由:根据接口 IP + 掩码自动推导网络地址和前缀
    pub fn add_direct_route(&mut self, interface: usize, ip: Ipv4Addr, netmask: Ipv4Addr) {
        self.routes.push(RouteEntry {
            network: network_address(ip, netmask),
            prefix_len: netmask.prefix_len() as u8,
            next_hop: None,
            interface,
        });
    }

    // 添加默认路由:0.0.0.0/0,交给网关
    pub fn add_default_route(&mut self, interface: usize, gateway: Ipv4Addr) {
        self.routes.push(RouteEntry {
            network: Ipv4Addr { value: 0 },
            prefix_len: 0,
            next_hop: Some(gateway),
            interface,
        });
    }

    // 添加一条普通静态路由。多 Router 拓扑不能只靠直连和默认路由，
    // traceroute 实验会用它明确描述“目标网段 → 下一跳 → 出接口”。
    pub fn add_route(
        &mut self,
        network: Ipv4Addr,
        prefix_len: u8,
        next_hop: Ipv4Addr,
        interface: usize,
    ) {
        assert!(prefix_len <= 32, "IPv4 前缀长度必须在 0..=32");
        let mask = prefix_to_mask(prefix_len);
        self.routes.push(RouteEntry {
            network: network_address(network, mask),
            prefix_len,
            next_hop: Some(next_hop),
            interface,
        });
    }
}

// ========== 路由器接口(一张网卡) ==========
pub struct Interface {
    pub name: String,      // 接口名,如 "eth0"
    pub ip: Ipv4Addr,      // 接口 IP
    pub netmask: Ipv4Addr, // 子网掩码
    pub mac: MacAddr,      // 接口 MAC
}

impl Interface {
    pub fn new(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr, mac: MacAddr) -> Self {
        Interface {
            name: name.to_string(),
            ip,
            netmask,
            mac,
        }
    }

    // 判断某个 IP 是否落在本接口所在的子网内
    pub fn in_subnet(&self, ip: Ipv4Addr) -> bool {
        same_subnet(self.ip, ip, self.netmask)
    }
}

// ========== 路由器(多接口 + 路由表 + TTL 递减) ==========
pub struct Router {
    pub name: String,                // 路由器名,如 "R1"
    pub interfaces: Vec<Interface>,  // 接口列表(每个接口连一个子网)
    pub routing_table: RoutingTable, // 路由表
}

// 转发结果
pub enum ForwardOutcome {
    Forwarded {
        next_hop: Ipv4Addr, // 下一跳 IP(直连时就是目的 IP)
        iface: usize,       // 出接口索引
        src_mac: MacAddr,   // 出接口 MAC(重新封装的源 MAC)
    },
    TtlExceeded, // TTL 耗尽,丢弃(防环)
    NoRoute,     // 查不到路由,丢弃
}

// v0.6 的 Router 不再只报告“成功/失败”，而是返回下一步可执行的网络动作。
// Forward 保留原始 src/dst，只减少 TTL；Reply 则是 Router 新建的 ICMP 包。
pub enum RouterAction {
    Forward {
        packet: IpPacket,
        next_hop: Ipv4Addr,
        iface: usize,
        src_mac: MacAddr,
    },
    Reply {
        packet: IpPacket,
        next_hop: Ipv4Addr,
        iface: usize,
        src_mac: MacAddr,
    },
    Drop {
        reason: RouterDropReason,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouterDropReason {
    InvalidIncomingInterface,
    NoReturnRoute,
    InvalidOutgoingInterface,
}

impl Router {
    pub fn new(name: &str, interfaces: Vec<Interface>, routing_table: RoutingTable) -> Self {
        Router {
            name: name.to_string(),
            interfaces,
            routing_table,
        }
    }

    // 转发一个 IP 包:TTL-1 → 查路由表 → 决定出接口和下一跳,源 MAC 重新封装为出接口 MAC
    pub fn forward(&self, packet: &mut IpPacket) -> ForwardOutcome {
        packet.ttl = packet.ttl.saturating_sub(1); // 每经过一个路由器 TTL-1
        if packet.ttl == 0 {
            return ForwardOutcome::TtlExceeded; // 减到 0,丢弃
        }
        match self.routing_table.lookup(packet.dst) {
            Some(route) => {
                let iface = &self.interfaces[route.interface];
                ForwardOutcome::Forwarded {
                    next_hop: route.next_hop.unwrap_or(packet.dst), // 直连 → 下一跳就是目的本身
                    iface: route.interface,
                    src_mac: iface.mac, // L3(src/dst)不变,L2 源 MAC 换成出接口
                }
            }
            None => ForwardOutcome::NoRoute,
        }
    }

    // v0.6 的 IP 接收入口。incoming_iface 表示报文从哪个接口进入，方便检查
    // 拓扑并在后续版本中处理接口策略；真正的出口仍由路由表决定。
    pub fn receive_ip(&self, incoming_iface: usize, mut packet: IpPacket) -> RouterAction {
        if incoming_iface >= self.interfaces.len() {
            return RouterAction::Drop {
                reason: RouterDropReason::InvalidIncomingInterface,
            };
        }

        // TTL=1 的包不能再经过本路由器。Router 不转发原包，而是向源主机
        // 新建一个 ICMP Time Exceeded，这正是 traceroute 观察每一跳的基础。
        if packet.ttl <= 1 {
            return self
                .icmp_error_reply(&packet, IcmpPacket::time_exceeded(packet.src, packet.dst));
        }
        packet.ttl -= 1;

        match self.route_for(packet.dst) {
            Some((next_hop, iface, src_mac)) => RouterAction::Forward {
                packet,
                next_hop,
                iface,
                src_mac,
            },
            None => self.icmp_error_reply(
                &packet,
                IcmpPacket::destination_unreachable(packet.src, packet.dst),
            ),
        }
    }

    // 为 ICMP 错误包查“回源路由”。错误包的源 IP 使用返回路径的出口接口 IP，
    // 所以多接口 Router 发出的错误能够明确表示由哪一跳响应。
    fn icmp_error_reply(&self, original: &IpPacket, icmp: IcmpPacket) -> RouterAction {
        let Some(route) = self.routing_table.lookup(original.src) else {
            return RouterAction::Drop {
                reason: RouterDropReason::NoReturnRoute,
            };
        };
        let Some(interface) = self.interfaces.get(route.interface) else {
            return RouterAction::Drop {
                reason: RouterDropReason::InvalidOutgoingInterface,
            };
        };
        let next_hop = route.next_hop.unwrap_or(original.src);
        RouterAction::Reply {
            packet: IpPacket {
                src: interface.ip,
                dst: original.src,
                ttl: 64,
                payload: IpPayload::Icmp(icmp),
            },
            next_hop,
            iface: route.interface,
            src_mac: interface.mac,
        }
    }

    fn route_for(&self, destination: Ipv4Addr) -> Option<(Ipv4Addr, usize, MacAddr)> {
        let route = self.routing_table.lookup(destination)?;
        let interface = self.interfaces.get(route.interface)?;
        Some((
            route.next_hop.unwrap_or(destination),
            route.interface,
            interface.mac,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn two_interface_router() -> Router {
        let mask = Ipv4Addr { value: 0xFFFF_FF00 };
        let left = Interface::new(
            "left",
            Ipv4Addr { value: 0xC0A8_0101 },
            mask,
            MacAddr::new([0x02, 0, 0, 0, 1, 1]),
        );
        let right = Interface::new(
            "right",
            Ipv4Addr { value: 0x0A00_0001 },
            mask,
            MacAddr::new([0x02, 0, 0, 0, 2, 1]),
        );
        let mut routes = RoutingTable::new();
        routes.add_direct_route(0, left.ip, mask);
        routes.add_direct_route(1, right.ip, mask);
        Router::new("R1", vec![left, right], routes)
    }

    fn data_packet(destination: u32, ttl: u8) -> IpPacket {
        IpPacket {
            src: Ipv4Addr { value: 0xC0A8_0102 },
            dst: Ipv4Addr { value: destination },
            ttl,
            payload: IpPayload::Data("probe".to_string()),
        }
    }

    #[test]
    fn router_forwards_packet_and_decrements_ttl() {
        let router = two_interface_router();
        match router.receive_ip(0, data_packet(0x0A00_0002, 64)) {
            RouterAction::Forward {
                packet,
                next_hop,
                iface,
                ..
            } => {
                assert_eq!(packet.ttl, 63);
                assert_eq!(next_hop, Ipv4Addr { value: 0x0A00_0002 });
                assert_eq!(iface, 1);
            }
            _ => panic!("应该转发到右侧网段"),
        }
    }

    #[test]
    fn ttl_expiry_creates_time_exceeded_reply() {
        let router = two_interface_router();
        match router.receive_ip(0, data_packet(0x0A00_0002, 1)) {
            RouterAction::Reply { packet, iface, .. } => {
                assert_eq!(packet.src, Ipv4Addr { value: 0xC0A8_0101 });
                assert_eq!(packet.dst, Ipv4Addr { value: 0xC0A8_0102 });
                assert_eq!(iface, 0);
                assert_eq!(
                    packet.payload,
                    IpPayload::Icmp(IcmpPacket::time_exceeded(
                        Ipv4Addr { value: 0xC0A8_0102 },
                        Ipv4Addr { value: 0x0A00_0002 },
                    ))
                );
            }
            _ => panic!("TTL=1 应生成 ICMP Time Exceeded"),
        }
    }

    #[test]
    fn missing_route_creates_destination_unreachable_reply() {
        let router = two_interface_router();
        match router.receive_ip(0, data_packet(0xAC10_0002, 64)) {
            RouterAction::Reply { packet, .. } => assert_eq!(
                packet.payload,
                IpPayload::Icmp(IcmpPacket::destination_unreachable(
                    Ipv4Addr { value: 0xC0A8_0102 },
                    Ipv4Addr { value: 0xAC10_0002 },
                ))
            ),
            _ => panic!("无路由应生成 ICMP Destination Unreachable"),
        }
    }
}
