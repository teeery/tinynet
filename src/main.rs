use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

// ========== 二层:MAC 地址 ==========
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct MacAddr([u8; 6]);

impl MacAddr {
    fn new(bytes: [u8; 6]) -> Self {
        MacAddr(bytes)
    }
    // 广播地址 ff:ff:ff:ff:ff:ff
    fn broadcast() -> Self {
        MacAddr([0xFF; 6])
    }
    fn to_string(&self) -> String {
        self.0.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
    }
}

// ========== 三层:IPv4 地址 ==========
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
struct Ipv4Addr {
    value: u32,
}

impl Ipv4Addr {
    // 转成点分十进制，例如 "192.168.10.37"
    fn to_dotted(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            (self.value >> 24) & 0xFF,
            (self.value >> 16) & 0xFF,
            (self.value >> 8) & 0xFF,
            self.value & 0xFF
        )
    }
    // 子网掩码转前缀长度，例如 255.255.255.224 -> 27
    fn prefix_len(&self) -> u32 {
        self.value.leading_ones()
    }
}

// 计算网络地址
fn network_address(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr { value: ip.value & mask.value }
}
// 判断两个 IP 是否在同一子网
fn same_subnet(my_ip: Ipv4Addr, dst_ip: Ipv4Addr, mask: Ipv4Addr) -> bool {
    network_address(my_ip, mask).value == network_address(dst_ip, mask).value
}

// ========== ARP 报文 ==========
struct ArpPacket {
    request: bool, // true=请求, false=响应
    sender_ip: Ipv4Addr,
    sender_mac: MacAddr,
    target_ip: Ipv4Addr,
    target_mac: Option<MacAddr>, // 请求时 None,响应时 Some(回应者的 MAC)
}

// ========== 以太网帧 ==========
enum EthernetPayload {
    Arp(ArpPacket),
    Data(String), // 直接携带数据(IP 分层留到 v0.3)
}

struct EthernetFrame {
    src: MacAddr,
    dst: MacAddr,
    payload: EthernetPayload,
}

// ========== 主机 ==========
struct Host {
    name: String,                                        // 主机名
    ip: Ipv4Addr,                                        // IP 地址
    netmask: Ipv4Addr,                                   // 子网掩码
    gateway: Ipv4Addr,                                   // 网关
    mac: MacAddr,                                        // MAC 地址
    arp_cache: RefCell<HashMap<Ipv4Addr, MacAddr>>,      // ARP 缓存:IP -> MAC
}

impl Host {
    fn new(name: &str, ip: Ipv4Addr, netmask: Ipv4Addr, gateway: Ipv4Addr, mac: MacAddr) -> Self {
        Host {
            name: name.to_string(),
            ip,
            netmask,
            gateway,
            mac,
            arp_cache: RefCell::new(HashMap::new()),
        }
    }

    // 发送数据:先解析目标 MAC(必要时广播 ARP 请求),再发数据帧
    fn send_to(&self, dst_ip: Ipv4Addr, data: &str, switch: &mut Switch) {
        println!("[{}] 准备发送数据到 {}", self.name, dst_ip.to_dotted());

        // 路由决策:确定下一跳(同子网 → 目的 IP,跨子网 → 网关)
        // IP 决定最终目的地;路由决定下一跳;ARP 只负责解析下一跳。
        let next_hop_ip = self.next_hop(dst_ip);

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
                    payload: EthernetPayload::Data(data.to_string()),
                };
                switch.forward(frame);
            }
            None => {
                println!("[{}] 无法解析 {} 的 MAC,发送失败", self.name, next_hop_ip.to_dotted());
            }
        }
    }

    // 收到帧后的处理;若需要回应(如 ARP 响应),返回要回发的帧
    fn receive(&self, frame: &EthernetFrame) -> Option<EthernetFrame> {
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
            EthernetPayload::Data(data) => {
                if frame.dst == self.mac || frame.dst == MacAddr::broadcast() {
                    println!("[{}] 收到数据: {}", self.name, data);
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

    // 路由决策:根据目的 IP 是否同子网,返回下一跳 IP(纯计算,不打印)
    // 同子网 → 直接交付(下一跳 = 目的 IP);跨子网 → 间接交付(下一跳 = 网关)
    fn next_hop(&self, dst_ip: Ipv4Addr) -> Ipv4Addr {
        if same_subnet(self.ip, dst_ip, self.netmask) {
            dst_ip
        } else {
            self.gateway
        }
    }

    // v0.1 遗留:L3 路由决策演示(打印决策过程,供教学观察)
    fn explain_route(&self, dst_ip: Ipv4Addr) -> Ipv4Addr {
        let src_net = network_address(self.ip, self.netmask);
        let dst_net = network_address(dst_ip, self.netmask);
        let prefix = self.netmask.prefix_len();

        let same = same_subnet(self.ip, dst_ip, self.netmask);
        let next_ip = self.next_hop(dst_ip);
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
            next = next_ip.to_dotted(),
        );

        next_ip
    }
}

// ========== 交换机 ==========
struct Switch {
    ports: HashMap<usize, Rc<Host>>,    // 端口号 -> 主机
    mac_table: HashMap<MacAddr, usize>, // MAC 地址表:MAC -> 端口号
}

impl Switch {
    fn new() -> Self {
        Switch { ports: HashMap::new(), mac_table: HashMap::new() }
    }

    fn connect(&mut self, port: usize, host: Rc<Host>) {
        self.ports.insert(port, host);
    }

    // 找到帧的来源端口(现实中硬件直接知道入端口;这里通过 MAC 反查模拟)
    fn source_port(&self, mac: MacAddr) -> Option<usize> {
        self.ports.iter().find(|(_, h)| h.mac == mac).map(|(p, _)| *p)
    }

    // 转发一帧:MAC Learning + 查表 + 单播/广播
    fn forward(&mut self, frame: EthernetFrame) {
        let src_port = self.source_port(frame.src);

        // 1. MAC Learning:记下「源 MAC -> 来源端口」
        if let Some(port) = src_port {
            if self.mac_table.insert(frame.src, port).is_none() {
                println!("[交换机] 学习 {} -> 端口{}", frame.src.to_string(), port);
            }
        }

        // 2. 查表确定目标端口
        let targets: Vec<usize> = match self.mac_table.get(&frame.dst) {
            Some(&port) => {
                println!("[交换机] 查表命中 {} -> 端口{}", frame.dst.to_string(), port);
                vec![port]
            }
            None => {
                println!("[交换机] 查表未命中,广播到所有其他端口");
                self.ports
                    .keys()
                    .copied()
                    .filter(|&p| Some(p) != src_port)
                    .collect()
            }
        };

        // 3. 投递
        for port in targets {
            let host = self.ports.get(&port).cloned();
            if let Some(host) = host {
                if let Some(reply) = host.receive(&frame) {
                    self.forward(reply); // 收到回应(ARP 响应),继续转发
                }
            }
        }
    }
}

fn main() {
    // ========== v0.1:L3 路由决策(下一跳判定) ==========
    let alice = Host::new(
        "主机A",
        Ipv4Addr { value: 0xC0A80A25 }, // 192.168.10.37
        Ipv4Addr { value: 0xFFFFFFE0 }, // 255.255.255.224 (/27)
        Ipv4Addr { value: 0xC0A80A21 }, // 网关 192.168.10.33
        MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]),
    );

    println!("========== 场景一：同一子网 ==========");
    alice.explain_route(Ipv4Addr { value: 0xC0A80A32 }); // 192.168.10.50
    println!();

    println!("========== 场景二：不同子网 ==========");
    alice.explain_route(Ipv4Addr { value: 0xC0A80A46 }); // 192.168.10.70
    println!();

    // ========== v0.2:二层交换(ARP + MAC 学习 + 广播) ==========
    let a = Rc::new(Host::new(
        "主机A",
        Ipv4Addr { value: 0xC0A80A25 }, // 192.168.10.37
        Ipv4Addr { value: 0xFFFFFFE0 },
        Ipv4Addr { value: 0xC0A80A21 },
        MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]),
    ));
    let b = Rc::new(Host::new(
        "主机B",
        Ipv4Addr { value: 0xC0A80A32 }, // 192.168.10.50
        Ipv4Addr { value: 0xFFFFFFE0 },
        Ipv4Addr { value: 0xC0A80A21 },
        MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02]),
    ));
    let c = Rc::new(Host::new(
        "主机C",
        Ipv4Addr { value: 0xC0A80A46 }, // 192.168.10.70
        Ipv4Addr { value: 0xFFFFFFE0 },
        Ipv4Addr { value: 0xC0A80A21 },
        MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x03]),
    ));

    let mut sw = Switch::new();
    sw.connect(0, a.clone());
    sw.connect(1, b.clone());
    sw.connect(2, c.clone());

    println!("========== v0.2 场景一:A 第一次给 B 发数据(触发 ARP + 广播) ==========");
    a.send_to(Ipv4Addr { value: 0xC0A80A32 }, "hello B", &mut sw);
    println!();

    println!("========== v0.2 场景二:A 再给 B 发数据(缓存命中,直接单播) ==========");
    a.send_to(Ipv4Addr { value: 0xC0A80A32 }, "hello again", &mut sw);
    println!();

    println!("========== v0.2 场景三:B 给 A 回数据(反向 ARP 学习) ==========");
    b.send_to(Ipv4Addr { value: 0xC0A80A25 }, "hi A", &mut sw);
}
