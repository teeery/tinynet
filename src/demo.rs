use std::rc::Rc;

use crate::address::{Ipv4Addr, MacAddr};
use crate::host::Host;
use crate::ospf::{Link, Topology};
use crate::packet::IpPacket;
use crate::routing::{ForwardOutcome, Interface, Router, RoutingTable};
use crate::switch::Switch;

// ========== v0.1:L3 路由决策演示 ==========
pub fn demo_v01() {
    println!("========== v0.1:路由决策演示(同子网直连 / 跨子网网关) ==========");

    let ip = Ipv4Addr { value: 0xC0A80A25 };      // 192.168.10.37
    let netmask = Ipv4Addr { value: 0xFFFFFFE0 }; // /27
    let gateway = Ipv4Addr { value: 0xC0A80A21 }; // 网关 192.168.10.33
    let mac = MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]);

    let mut rt = RoutingTable::new();
    rt.add_direct_route(0, ip, netmask);
    rt.add_default_route(0, gateway);

    let alice = Host::new("主机A", ip, netmask, rt, mac);

    println!("========== 场景一：同一子网 ==========");
    let _ = alice.explain_route(Ipv4Addr { value: 0xC0A80A32 }); // 192.168.10.50
    println!();

    println!("========== 场景二：不同子网 ==========");
    let _ = alice.explain_route(Ipv4Addr { value: 0xC0A80A46 }); // 192.168.10.70
    println!();
}

// ========== v0.2:二层交换(ARP + MAC 学习 + 广播) ==========
pub fn demo_v02() {
    println!("========== v0.2:二层交换(ARP + MAC 学习 + 广播) ==========");

    // 快速建一个「只有直连路由」的主机(同子网,无需默认路由)
    let make_host = |name: &str, ip: Ipv4Addr, mac: MacAddr| -> Rc<Host> {
        let netmask = Ipv4Addr { value: 0xFFFFFFE0 }; // /27
        let mut rt = RoutingTable::new();
        rt.add_direct_route(0, ip, netmask);
        Rc::new(Host::new(name, ip, netmask, rt, mac))
    };

    let a = make_host("主机A", Ipv4Addr { value: 0xC0A80A25 }, MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]));
    let b = make_host("主机B", Ipv4Addr { value: 0xC0A80A32 }, MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02]));
    let c = make_host("主机C", Ipv4Addr { value: 0xC0A80A46 }, MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x03]));

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
    println!();
}

// ========== v0.3:路由表(最长前缀匹配) ==========
pub fn demo_v03() {
    println!("========== v0.3:路由表(最长前缀匹配) ==========");

    let ip = Ipv4Addr { value: 0xC0A80A25 };      // 192.168.10.37
    let netmask = Ipv4Addr { value: 0xFFFFFFE0 }; // /27
    let gateway = Ipv4Addr { value: 0xC0A80A21 }; // 网关 192.168.10.33
    let mac = MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]);

    // 配两条路由:直连 + 默认
    let mut rt = RoutingTable::new();
    rt.add_direct_route(0, ip, netmask);   // 192.168.10.32/27,直连
    rt.add_default_route(0, gateway);      // 0.0.0.0/0 → 网关

    let host = Host::new("主机A", ip, netmask, rt, mac);

    println!("--- 同子网:命中直连路由(/27) ---");
    match host.next_hop(Ipv4Addr { value: 0xC0A80A32 }) { // 192.168.10.50
        Some(hop) => println!("下一跳 = {} (直连)", hop.to_dotted()),
        None => println!("不可达"),
    }
    println!();

    println!("--- 跨子网:命中默认路由(/0) ---");
    match host.next_hop(Ipv4Addr { value: 0x0A000008 }) { // 10.0.0.8
        Some(hop) => println!("下一跳 = {} (走网关)", hop.to_dotted()),
        None => println!("不可达"),
    }
    println!();

    // 教学观察:直接看查表命中了哪条路由
    println!("--- 观察:lookup 命中了哪条 ---");
    if let Some(r) = host.routing_table.lookup(Ipv4Addr { value: 0xC0A80A32 }) {
        println!("192.168.10.50 命中 {} /{}", r.network.to_dotted(), r.prefix_len);
    }
    if let Some(r) = host.routing_table.lookup(Ipv4Addr { value: 0x0A000008 }) {
        println!("10.0.0.8 命中 {} /{}", r.network.to_dotted(), r.prefix_len);
    }
}

// ========== v0.3:TTL(生存时间,防环) ==========
pub fn demo_v04() {
    println!("========== v0.3:TTL(生存时间,防环) ==========");

    // 造一个路由器:直连 192.168.10.32/27 + 默认路由
    let router_ip = Ipv4Addr { value: 0xC0A80A21 }; // 网关 192.168.10.33
    let netmask = Ipv4Addr { value: 0xFFFFFFE0 };   // /27
    let mut rt = RoutingTable::new();
    rt.add_direct_route(0, router_ip, netmask);
    rt.add_default_route(0, router_ip);
    let router = Router::new(
        "R1",
        vec![Interface::new("eth0", router_ip, netmask, MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x01]))],
        rt,
    );

    let src = Ipv4Addr { value: 0xC0A80A25 }; // 192.168.10.37
    let dst = Ipv4Addr { value: 0x0A000008 }; // 10.0.0.8(走默认路由)

    // 场景一:TTL=2,经过路由器后变 1,成功转发
    println!("--- 场景一:TTL=2,转发成功 ---");
    let mut pkt1 = IpPacket { src, dst, ttl: 2, payload: "hello".to_string() };
    match router.forward(&mut pkt1) {
        ForwardOutcome::Forwarded { next_hop, .. } => println!("转发到下一跳 {},剩余 TTL={}", next_hop.to_dotted(), pkt1.ttl),
        ForwardOutcome::TtlExceeded => println!("TTL 耗尽,丢弃"),
        ForwardOutcome::NoRoute => println!("无路由,丢弃"),
    }
    println!();

    // 场景二:TTL=1,经过路由器后变 0,被丢弃
    println!("--- 场景二:TTL=1,耗尽丢弃 ---");
    let mut pkt2 = IpPacket { src, dst, ttl: 1, payload: "hello".to_string() };
    match router.forward(&mut pkt2) {
        ForwardOutcome::Forwarded { next_hop, .. } => println!("转发到下一跳 {}", next_hop.to_dotted()),
        ForwardOutcome::TtlExceeded => println!("TTL 耗尽,丢弃(防止环路)"),
        ForwardOutcome::NoRoute => println!("无路由,丢弃"),
    }
    println!();

    // 场景三:TTL=3,连续转发模拟多跳,直到耗尽
    println!("--- 场景三:TTL=3 连续转发,模拟多跳 ---");
    let mut pkt3 = IpPacket { src, dst, ttl: 3, payload: "hello".to_string() };
    for hop in 1..=4 {
        match router.forward(&mut pkt3) {
            ForwardOutcome::Forwarded { next_hop, .. } => println!("第 {} 跳:转发到 {},剩余 TTL={}", hop, next_hop.to_dotted(), pkt3.ttl),
            ForwardOutcome::TtlExceeded => {
                println!("第 {} 跳:TTL 耗尽,丢弃", hop);
                break;
            }
            ForwardOutcome::NoRoute => {
                println!("第 {} 跳:无路由,丢弃", hop);
                break;
            }
        }
    }
}

// ========== v0.3:多接口路由器(跨网段真正转发) ==========
pub fn demo_v05() {
    println!("========== v0.3:多接口路由器(跨网段转发) ==========");

    // 双接口路由器:
    //   eth0 → 192.168.10.0/24(左侧 LAN)
    //   eth1 → 10.0.0.0/24(右侧 LAN)
    let eth0 = Interface::new(
        "eth0",
        Ipv4Addr { value: 0xC0A80A01 }, // 192.168.10.1
        Ipv4Addr { value: 0xFFFFFF00 }, // /24
        MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x01]),
    );
    let eth1 = Interface::new(
        "eth1",
        Ipv4Addr { value: 0x0A000001 }, // 10.0.0.1
        Ipv4Addr { value: 0xFFFFFF00 }, // /24
        MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x02]),
    );

    // 路由表:两条直连路由,各自指定出接口
    let mut rt = RoutingTable::new();
    rt.add_direct_route(0, eth0.ip, eth0.netmask); // 192.168.10.0/24 → eth0
    rt.add_direct_route(1, eth1.ip, eth1.netmask); // 10.0.0.0/24 → eth1

    let mut router = Router::new("R1", vec![eth0, eth1], rt);

    let src = Ipv4Addr { value: 0xC0A80A05 }; // 192.168.10.5

    println!("--- 场景一:跨网段转发(eth0 进 → eth1 出) ---");
    let mut pkt1 = IpPacket { src, dst: Ipv4Addr { value: 0x0A000008 }, ttl: 64, payload: "hello across".to_string() };
    let in_eth0 = router.interfaces[0].in_subnet(pkt1.dst);
    println!("目的 {} 在 eth0 子网内吗? {} → 需要路由转发", pkt1.dst.to_dotted(), in_eth0);
    match router.forward(&mut pkt1) {
        ForwardOutcome::Forwarded { next_hop, iface, src_mac } => {
            let i = &router.interfaces[iface];
            println!("{} 查表命中直连路由,从 {} 发出", router.name, i.name);
            println!("下一跳 = {} (直连)", next_hop.to_dotted());
            println!("L3 不变: src={} dst={};L2 重新封装: 源 MAC={}", pkt1.src.to_dotted(), pkt1.dst.to_dotted(), src_mac.to_string());
            println!("剩余 TTL={}", pkt1.ttl);
        }
        ForwardOutcome::TtlExceeded => println!("TTL 耗尽"),
        ForwardOutcome::NoRoute => println!("无路由"),
    }
    println!();

    println!("--- 场景二:同侧子网(eth0 进 → eth0 出) ---");
    let mut pkt2 = IpPacket { src, dst: Ipv4Addr { value: 0xC0A80A63 }, ttl: 64, payload: "hello same subnet".to_string() };
    match router.forward(&mut pkt2) {
        ForwardOutcome::Forwarded { next_hop, iface, .. } => {
            let i = &router.interfaces[iface];
            println!("从 {} 发出,下一跳 = {} (直连)", i.name, next_hop.to_dotted());
        }
        _ => unreachable!(),
    }
    println!();

    println!("--- 场景三:无路由(查不到,丢弃) ---");
    let mut pkt3 = IpPacket { src, dst: Ipv4Addr { value: 0xAC100005 }, ttl: 64, payload: "hello nowhere".to_string() };
    match router.forward(&mut pkt3) {
        ForwardOutcome::NoRoute => println!("172.16.0.5 无匹配路由,丢弃"),
        _ => unreachable!(),
    }
    println!();

    println!("--- 场景四:补一条默认路由,走网关(间接转发) ---");
    let gateway = Ipv4Addr { value: 0x0A0000FE }; // 10.0.0.254
    router.routing_table.add_default_route(1, gateway);
    let mut pkt4 = IpPacket { src, dst: Ipv4Addr { value: 0xAC100005 }, ttl: 64, payload: "hello via gateway".to_string() };
    match router.forward(&mut pkt4) {
        ForwardOutcome::Forwarded { next_hop, iface, .. } => {
            let i = &router.interfaces[iface];
            println!("命中默认路由,从 {} 发出,下一跳 = {} (网关)", i.name, next_hop.to_dotted());
        }
        _ => unreachable!(),
    }
    println!();

    println!("--- 场景五:TTL 递减,直到耗尽(防环) ---");
    let mut pkt5 = IpPacket { src, dst: Ipv4Addr { value: 0x0A000008 }, ttl: 3, payload: "hello ttl".to_string() };
    for hop in 1..=4 {
        match router.forward(&mut pkt5) {
            ForwardOutcome::Forwarded { next_hop, .. } => println!("第 {} 跳:转发到 {},剩余 TTL={}", hop, next_hop.to_dotted(), pkt5.ttl),
            ForwardOutcome::TtlExceeded => {
                println!("第 {} 跳:TTL 耗尽,丢弃", hop);
                break;
            }
            ForwardOutcome::NoRoute => {
                println!("第 {} 跳:无路由,丢弃", hop);
                break;
            }
        }
    }
}

// ========== 简化版 OSPF:动态路由(SPF 最短路径优先) ==========
pub fn demo_v06() {
    println!("========== 简化版 OSPF:动态路由(SPF 最短路径优先) ==========");

    // 初始拓扑(无向,数字是链路开销):
    //          R1
    //         /  \
    //       2/    \6
    //       /      \
    //      R2 --2-- R3
    //       \      /
    //       2\    /1
    //         \  /
    //          R4
    let mut topo = Topology::new(vec![
        Link { from: "R1", to: "R2", cost: 2 },
        Link { from: "R1", to: "R3", cost: 6 },
        Link { from: "R2", to: "R3", cost: 2 },
        Link { from: "R2", to: "R4", cost: 2 },
        Link { from: "R3", to: "R4", cost: 1 },
    ]);

    println!("--- 初始:R1 跑一次 SPF ---");
    topo.print_spf("R1");
    println!();

    println!("--- 模拟 R2-R4 链路 DOWN,重新计算 ---");
    topo.bring_link_down("R2", "R4");
    topo.print_spf("R1");
    println!();

    println!("说明:R4 的开销从 4 变 5,R1 自动绕道 R2-R3-R4,无需人工改配置。");
}
