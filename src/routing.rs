use crate::address::{network_address, prefix_to_mask, same_subnet, Ipv4Addr, MacAddr};
use crate::packet::IpPacket;

// ========== v0.3:路由表 ==========

// 一条路由条目
pub struct RouteEntry {
    pub network: Ipv4Addr,           // 目的网络地址
    pub prefix_len: u8,              // 前缀长度
    pub next_hop: Option<Ipv4Addr>,  // None 表示直连,Some(IP) = 经过网关
    pub interface: usize,            // 出接口索引(指向 Router.interfaces)
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
}

// ========== 路由器接口(一张网卡) ==========
pub struct Interface {
    pub name: String,       // 接口名,如 "eth0"
    pub ip: Ipv4Addr,       // 接口 IP
    pub netmask: Ipv4Addr,  // 子网掩码
    pub mac: MacAddr,       // 接口 MAC
}

impl Interface {
    pub fn new(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr, mac: MacAddr) -> Self {
        Interface { name: name.to_string(), ip, netmask, mac }
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

impl Router {
    pub fn new(name: &str, interfaces: Vec<Interface>, routing_table: RoutingTable) -> Self {
        Router { name: name.to_string(), interfaces, routing_table }
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
}
