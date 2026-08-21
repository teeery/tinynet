//! TinyNet 教学 Demo 总览。
//!
//! 主线严格按照 v0.1 → v0.7 → v1.0 排列。每个版本只有一个公开入口，
//! 版本内部的多个场景使用私有函数拆分；OSPF/BGP 放在主线之后作为扩展实验。
//!
//! - v0.1：Packet、Node、Link、Forwarding
//! - v0.2：Ethernet、MAC、Switch、Learning、Broadcast
//! - v0.3：IP、Subnet、Routing Table、Router、TTL
//! - v0.4：Seq、ACK、Timeout、Retransmission（GBN / SR）
//! - v0.5：TCP Handshake、Sliding Window、Flow Control、Close
//! - v0.6：ARP、ICMP、ping、traceroute
//! - v0.7：DNS over UDP、HTTP over TCP
//! - v1.0：EventQueue 驱动的 Mini Internet；Browser 正式验收，Chat 附加演示

use std::rc::Rc;

use crate::address::{Ipv4Addr, MacAddr};
use crate::bgp::{BgpPolicy, BgpRoute, Prefix, select_bgp_route};
use crate::chat::ChatApp;
use crate::dns::{
    DNS_PORT, DnsExchange, DnsMessage, DnsRecord, DnsRecordData, DnsRecordType, DnsResolver,
    DnsServer,
};
use crate::host::Host;
use crate::http::{HttpServer, HttpSession};
use crate::internet::{InternetTrace, MiniInternet};
use crate::network::{Endpoint, Network, NetworkEvent, NodeKind, SendDisposition};
use crate::ospf::{Link, Topology};
use crate::packet::{IpPacket, IpPayload};
use crate::reliable::{GbnReceiver, GbnSender, LossyNetwork, SrReceiver, SrSender};
use crate::routing::{ForwardOutcome, Interface, Router, RouterAction, RoutingTable};
use crate::switch::Switch;
use crate::tcp::{TcpConnection, TcpSegment};
use crate::traceroute::{TraceOutcome, TraceRouter, trace_route};
use crate::udp::{UdpDatagram, UdpPayload};

// =============================================================================
// v0.1：Packet 穿越节点
// 目标：理解“网络 = 节点 + 链路 + 转发”，暂不讨论 MAC、子网和可靠性。
// =============================================================================
pub fn demo_v01_packet_forwarding() {
    println!("========== v0.1：Packet 穿越节点 ==========");
    let packet = IpPacket {
        src: Ipv4Addr { value: 0x0A00_0001 },
        dst: Ipv4Addr { value: 0x0A00_0002 },
        ttl: 64,
        payload: IpPayload::Data("Hello TinyNet".to_string()),
    };
    let path = ["Host-A", "Router-1", "Host-B"];
    println!(
        "[Packet] {} → {}，payload=Hello TinyNet",
        packet.src.to_dotted(),
        packet.dst.to_dotted()
    );
    for link in path.windows(2) {
        println!("[Link] {} → {}：转发 Packet", link[0], link[1]);
    }
    println!("结论：节点处理 Packet，链路连接节点，逐跳转发形成网络。\n");
}

// =============================================================================
// v0.2：Ethernet LAN
// 目标：MAC、Switch、MAC Learning 与 Broadcast。ARP 在这里仅用于触发广播场景。
// =============================================================================
pub fn demo_v02_ethernet_lan() {
    demo_v02_switch_learning();
}

fn demo_v02_switch_learning() {
    println!("========== v0.2：Ethernet LAN ==========");
    // 快速建一个「只有直连路由」的主机(同子网,无需默认路由)
    let make_host = |name: &str, ip: Ipv4Addr, mac: MacAddr| -> Rc<Host> {
        let netmask = Ipv4Addr { value: 0xFFFFFFE0 }; // /27
        let mut rt = RoutingTable::new();
        rt.add_direct_route(0, ip, netmask);
        Rc::new(Host::new(name, ip, netmask, rt, mac))
    };

    let a = make_host(
        "主机A",
        Ipv4Addr { value: 0xC0A80A25 },
        MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]),
    );
    let b = make_host(
        "主机B",
        Ipv4Addr { value: 0xC0A80A32 },
        MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x02]),
    );
    let c = make_host(
        "主机C",
        Ipv4Addr { value: 0xC0A80A46 },
        MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x03]),
    );

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

// =============================================================================
// v0.3：IP Internet
// 目标：IP、Subnet、Routing Table、TTL 与多接口 Router。
// =============================================================================
pub fn demo_v03_ip_internet() {
    demo_v03_host_route_decision();
    demo_v03_routing_table();
    demo_v03_ttl();
    demo_v03_multi_interface_router();
}

fn demo_v03_host_route_decision() {
    println!("========== v0.3 场景一：Subnet 与下一跳 ==========");
    let ip = Ipv4Addr { value: 0xC0A80A25 };
    let netmask = Ipv4Addr { value: 0xFFFFFFE0 };
    let gateway = Ipv4Addr { value: 0xC0A80A21 };
    let mut routes = RoutingTable::new();
    routes.add_direct_route(0, ip, netmask);
    routes.add_default_route(0, gateway);
    let host = Host::new(
        "主机A",
        ip,
        netmask,
        routes,
        MacAddr::new([0xAA, 0xBB, 0xCC, 0, 0, 1]),
    );
    let _ = host.explain_route(Ipv4Addr { value: 0xC0A80A32 });
    let _ = host.explain_route(Ipv4Addr { value: 0xC0A80A46 });
    println!();
}

fn demo_v03_routing_table() {
    println!("========== v0.3 场景二：Routing Table 最长前缀匹配 ==========");

    let ip = Ipv4Addr { value: 0xC0A80A25 }; // 192.168.10.37
    let netmask = Ipv4Addr { value: 0xFFFFFFE0 }; // /27
    let gateway = Ipv4Addr { value: 0xC0A80A21 }; // 网关 192.168.10.33
    let mac = MacAddr::new([0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01]);

    // 配两条路由:直连 + 默认
    let mut rt = RoutingTable::new();
    rt.add_direct_route(0, ip, netmask); // 192.168.10.32/27,直连
    rt.add_default_route(0, gateway); // 0.0.0.0/0 → 网关

    let host = Host::new("主机A", ip, netmask, rt, mac);

    println!("--- 同子网:命中直连路由(/27) ---");
    match host.next_hop(Ipv4Addr { value: 0xC0A80A32 }) {
        // 192.168.10.50
        Some(hop) => println!("下一跳 = {} (直连)", hop.to_dotted()),
        None => println!("不可达"),
    }
    println!();

    println!("--- 跨子网:命中默认路由(/0) ---");
    match host.next_hop(Ipv4Addr { value: 0x0A000008 }) {
        // 10.0.0.8
        Some(hop) => println!("下一跳 = {} (走网关)", hop.to_dotted()),
        None => println!("不可达"),
    }
    println!();

    // 教学观察:直接看查表命中了哪条路由
    println!("--- 观察:lookup 命中了哪条 ---");
    if let Some(r) = host.routing_table.lookup(Ipv4Addr { value: 0xC0A80A32 }) {
        println!(
            "192.168.10.50 命中 {} /{}",
            r.network.to_dotted(),
            r.prefix_len
        );
    }
    if let Some(r) = host.routing_table.lookup(Ipv4Addr { value: 0x0A000008 }) {
        println!("10.0.0.8 命中 {} /{}", r.network.to_dotted(), r.prefix_len);
    }
}

// v0.3 场景三：TTL 防止路由环路。
fn demo_v03_ttl() {
    println!("========== v0.3 场景三：TTL（生存时间） ==========");

    // 造一个路由器:直连 192.168.10.32/27 + 默认路由
    let router_ip = Ipv4Addr { value: 0xC0A80A21 }; // 网关 192.168.10.33
    let netmask = Ipv4Addr { value: 0xFFFFFFE0 }; // /27
    let mut rt = RoutingTable::new();
    rt.add_direct_route(0, router_ip, netmask);
    rt.add_default_route(0, router_ip);
    let router = Router::new(
        "R1",
        vec![Interface::new(
            "eth0",
            router_ip,
            netmask,
            MacAddr::new([0x00, 0x11, 0x22, 0x33, 0x44, 0x01]),
        )],
        rt,
    );

    let src = Ipv4Addr { value: 0xC0A80A25 }; // 192.168.10.37
    let dst = Ipv4Addr { value: 0x0A000008 }; // 10.0.0.8(走默认路由)

    // 场景一:TTL=2,经过路由器后变 1,成功转发
    println!("--- 场景一:TTL=2,转发成功 ---");
    let mut pkt1 = IpPacket {
        src,
        dst,
        ttl: 2,
        payload: IpPayload::Data("hello".to_string()),
    };
    match router.forward(&mut pkt1) {
        ForwardOutcome::Forwarded { next_hop, .. } => println!(
            "转发到下一跳 {},剩余 TTL={}",
            next_hop.to_dotted(),
            pkt1.ttl
        ),
        ForwardOutcome::TtlExceeded => println!("TTL 耗尽,丢弃"),
        ForwardOutcome::NoRoute => println!("无路由,丢弃"),
    }
    println!();

    // 场景二:TTL=1,经过路由器后变 0,被丢弃
    println!("--- 场景二:TTL=1,耗尽丢弃 ---");
    let mut pkt2 = IpPacket {
        src,
        dst,
        ttl: 1,
        payload: IpPayload::Data("hello".to_string()),
    };
    match router.forward(&mut pkt2) {
        ForwardOutcome::Forwarded { next_hop, .. } => {
            println!("转发到下一跳 {}", next_hop.to_dotted())
        }
        ForwardOutcome::TtlExceeded => println!("TTL 耗尽,丢弃(防止环路)"),
        ForwardOutcome::NoRoute => println!("无路由,丢弃"),
    }
    println!();

    // 场景三:TTL=3,连续转发模拟多跳,直到耗尽
    println!("--- 场景三:TTL=3 连续转发,模拟多跳 ---");
    let mut pkt3 = IpPacket {
        src,
        dst,
        ttl: 3,
        payload: IpPayload::Data("hello".to_string()),
    };
    for hop in 1..=4 {
        match router.forward(&mut pkt3) {
            ForwardOutcome::Forwarded { next_hop, .. } => println!(
                "第 {} 跳:转发到 {},剩余 TTL={}",
                hop,
                next_hop.to_dotted(),
                pkt3.ttl
            ),
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

// v0.3 场景四：多接口 Router 跨网段转发。
fn demo_v03_multi_interface_router() {
    println!("========== v0.3 场景四：多接口 Router ==========");

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
    let mut pkt1 = IpPacket {
        src,
        dst: Ipv4Addr { value: 0x0A000008 },
        ttl: 64,
        payload: IpPayload::Data("hello across".to_string()),
    };
    let in_eth0 = router.interfaces[0].in_subnet(pkt1.dst);
    println!(
        "目的 {} 在 eth0 子网内吗? {} → 需要路由转发",
        pkt1.dst.to_dotted(),
        in_eth0
    );
    match router.forward(&mut pkt1) {
        ForwardOutcome::Forwarded {
            next_hop,
            iface,
            src_mac,
        } => {
            let i = &router.interfaces[iface];
            println!("{} 查表命中直连路由,从 {} 发出", router.name, i.name);
            println!("下一跳 = {} (直连)", next_hop.to_dotted());
            println!(
                "L3 不变: src={} dst={};L2 重新封装: 源 MAC={}",
                pkt1.src.to_dotted(),
                pkt1.dst.to_dotted(),
                src_mac.to_string()
            );
            println!("剩余 TTL={}", pkt1.ttl);
        }
        ForwardOutcome::TtlExceeded => println!("TTL 耗尽"),
        ForwardOutcome::NoRoute => println!("无路由"),
    }
    println!();

    println!("--- 场景二:同侧子网(eth0 进 → eth0 出) ---");
    let mut pkt2 = IpPacket {
        src,
        dst: Ipv4Addr { value: 0xC0A80A63 },
        ttl: 64,
        payload: IpPayload::Data("hello same subnet".to_string()),
    };
    match router.forward(&mut pkt2) {
        ForwardOutcome::Forwarded {
            next_hop, iface, ..
        } => {
            let i = &router.interfaces[iface];
            println!(
                "从 {} 发出,下一跳 = {} (直连)",
                i.name,
                next_hop.to_dotted()
            );
        }
        _ => unreachable!(),
    }
    println!();

    println!("--- 场景三:无路由(查不到,丢弃) ---");
    let mut pkt3 = IpPacket {
        src,
        dst: Ipv4Addr { value: 0xAC100005 },
        ttl: 64,
        payload: IpPayload::Data("hello nowhere".to_string()),
    };
    match router.forward(&mut pkt3) {
        ForwardOutcome::NoRoute => println!("172.16.0.5 无匹配路由,丢弃"),
        _ => unreachable!(),
    }
    println!();

    println!("--- 场景四:补一条默认路由,走网关(间接转发) ---");
    let gateway = Ipv4Addr { value: 0x0A0000FE }; // 10.0.0.254
    router.routing_table.add_default_route(1, gateway);
    let mut pkt4 = IpPacket {
        src,
        dst: Ipv4Addr { value: 0xAC100005 },
        ttl: 64,
        payload: IpPayload::Data("hello via gateway".to_string()),
    };
    match router.forward(&mut pkt4) {
        ForwardOutcome::Forwarded {
            next_hop, iface, ..
        } => {
            let i = &router.interfaces[iface];
            println!(
                "命中默认路由,从 {} 发出,下一跳 = {} (网关)",
                i.name,
                next_hop.to_dotted()
            );
        }
        _ => unreachable!(),
    }
    println!();

    println!("--- 场景五:TTL 递减,直到耗尽(防环) ---");
    let mut pkt5 = IpPacket {
        src,
        dst: Ipv4Addr { value: 0x0A000008 },
        ttl: 3,
        payload: IpPayload::Data("hello ttl".to_string()),
    };
    for hop in 1..=4 {
        match router.forward(&mut pkt5) {
            ForwardOutcome::Forwarded { next_hop, .. } => println!(
                "第 {} 跳:转发到 {},剩余 TTL={}",
                hop,
                next_hop.to_dotted(),
                pkt5.ttl
            ),
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

// =============================================================================
// v0.4：可靠传输
// 目标：在丢包网络中观察 Seq、ACK、Timeout、Retransmission，以及 GBN/SR 差异。
// =============================================================================
pub fn demo_v04_reliable_transport() {
    const WINDOW_SIZE: u32 = 4;
    const TIMEOUT: u32 = 3;

    println!("========== v0.4：可靠传输（故意丢弃 seq=2） ==========");
    println!("核心机制：Seq + ACK + Timeout + Retransmission");
    println!();

    // 本次对照实验需要固定结果，所以使用 drop_once。若要观察随机丢包，可把网络
    // 替换成 LossyNetwork::random(丢包百分比, 随机种子)；相同种子可复现实验。
    let _random_loss_example = LossyNetwork::random(20, 0x5449_4e59);

    // 两次实验使用各自独立的网络，都会只丢弃 seq=2 的第一次发送。
    println!("--- GBN：乱序报文直接丢弃，超时后回退重传整个窗口 ---");
    let mut gbn_sender = GbnSender::new(WINDOW_SIZE, TIMEOUT);
    let mut gbn_receiver = GbnReceiver::new();
    let mut gbn_network = LossyNetwork::drop_once([2]);

    for seq in 1..=4 {
        let segment = gbn_sender.send(format!("message-{seq}")).unwrap();
        print!("send {}", segment.seq);
        match gbn_network.transmit(segment) {
            None => println!("  X（网络丢包）"),
            Some(segment) => {
                println!();
                let received_seq = segment.seq;
                let result = gbn_receiver.receive(segment);
                if result.delivered.is_empty() {
                    println!(
                        "recv {} -> drop（期望 seq={}）",
                        received_seq, gbn_receiver.expected_seq
                    );
                } else {
                    println!(
                        "recv {} -> deliver, ACK {}",
                        received_seq,
                        result.ack.unwrap()
                    );
                }
                gbn_sender.receive_ack(result.ack.unwrap());
            }
        }
    }

    let gbn_retransmissions = wait_for_gbn_timeout(&mut gbn_sender);
    println!("timeout {}", gbn_sender.send_base);
    println!("retransmit: {}", seq_list(&gbn_retransmissions));
    for segment in gbn_retransmissions {
        let result = gbn_receiver.receive(segment);
        gbn_sender.receive_ack(result.ack.unwrap());
    }
    println!(
        "GBN 完成：send_base={}，未确认队列={}",
        gbn_sender.send_base,
        gbn_sender.unacked_queue.len()
    );
    println!();

    println!("--- SR：乱序报文进入缓存，超时后只重传丢失报文 ---");
    let mut sr_sender = SrSender::new(WINDOW_SIZE, TIMEOUT);
    let mut sr_receiver = SrReceiver::new(WINDOW_SIZE);
    let mut sr_network = LossyNetwork::drop_once([2]);

    for seq in 1..=4 {
        let segment = sr_sender.send(format!("message-{seq}")).unwrap();
        print!("send {}", segment.seq);
        match sr_network.transmit(segment) {
            None => println!("  X（网络丢包）"),
            Some(segment) => {
                println!();
                let received_seq = segment.seq;
                let result = sr_receiver.receive(segment);
                if result.buffered {
                    println!(
                        "recv {} -> buffer, ACK {}",
                        received_seq,
                        result.ack.unwrap()
                    );
                } else {
                    println!(
                        "recv {} -> deliver, ACK {}",
                        received_seq,
                        result.ack.unwrap()
                    );
                }
                sr_sender.receive_ack(result.ack.unwrap());
            }
        }
    }

    let sr_retransmissions = wait_for_sr_timeout(&mut sr_sender);
    println!("timeout {}", sr_sender.send_base);
    println!("retransmit: {} only", seq_list(&sr_retransmissions));
    let mut delivered = Vec::new();
    for segment in sr_retransmissions {
        let result = sr_receiver.receive(segment);
        if let Some(ack) = result.ack {
            sr_sender.receive_ack(ack);
        }
        delivered.extend(result.delivered.into_iter().map(|segment| segment.seq));
    }
    println!(
        "deliver: {}",
        delivered
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!(
        "SR 完成：send_base={}，buffer={}，未确认队列={}",
        sr_sender.send_base,
        sr_receiver.buffer.len(),
        sr_sender.unacked_queue.len()
    );
    println!();

    println!("结论：GBN 接收端简单但会重复发送 3、4；SR 用缓存换来更少的重传。\n");
}

fn wait_for_gbn_timeout(sender: &mut GbnSender) -> Vec<crate::reliable::Segment> {
    loop {
        let retransmissions = sender.tick();
        if !retransmissions.is_empty() {
            return retransmissions;
        }
    }
}

fn wait_for_sr_timeout(sender: &mut SrSender) -> Vec<crate::reliable::Segment> {
    loop {
        let retransmissions = sender.tick();
        if !retransmissions.is_empty() {
            return retransmissions;
        }
    }
}

fn seq_list(segments: &[crate::reliable::Segment]) -> String {
    segments
        .iter()
        .map(|segment| segment.seq.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

// =============================================================================
// v0.5：TCP
// 目标：三次握手、滑动窗口、流量控制和四次挥手。
// =============================================================================
/*
Client 与 Server 三次握手。
Client 想发送 12 字节，但受服务端 rwnd=8 限制，只能先发送 8 字节。
服务端缓冲区满，通告零窗口，客户端暂停。
服务端应用读取 4 字节，窗口重新打开。
客户端发送剩余 4 字节。
双方执行完整四次挥手。
Client 等待 2MSL 后关闭。
*/
pub fn demo_v05_tcp() {
    println!("========== v0.5：TCP ==========");
    println!("场景：Client:50000 连接 Server:80，发送 12 字节数据后主动关闭。\n");

    // 客户端发送窗口为 12 字节；服务端接收缓冲区只有 8 字节。
    // 因此即使客户端愿意发送 12 字节，也必须服从服务端通告的 rwnd=8。
    let mut client = TcpConnection::client("Client", 50_000, 80, 1000, 12, 16);
    let mut server = TcpConnection::listener("Server", 80, 5000, 12, 8);

    println!("--- 一、三次握手 ---");
    let syn = client.connect().unwrap();
    print_tcp_segment("1. Client -> Server", &syn);
    println!("   Client: CLOSED -> {:?}", client.state);

    let syn_ack = server.receive(syn).unwrap().unwrap();
    print_tcp_segment("2. Server -> Client", &syn_ack);
    println!("   Server: LISTEN -> {:?}", server.state);

    let ack = client.receive(syn_ack).unwrap().unwrap();
    print_tcp_segment("3. Client -> Server", &ack);
    server.receive(ack).unwrap();
    println!(
        "   Client={:?}, Server={:?}：连接建立\n",
        client.state, server.state
    );

    println!("--- 二、滑动窗口与流量控制 ---");
    let data = b"ABCDEFGHIJKL"; // 12 字节，MSS=4，理论上分成 3 段。
    println!(
        "Client 想发送 12 字节；send_window=12，Server 通告 rwnd={}",
        client.peer_window
    );
    let first_batch = client.send_data(data, 4).unwrap();
    let first_sent: usize = first_batch
        .iter()
        .map(|segment| segment.payload.len())
        .sum();
    println!(
        "有效窗口 min(12, {})=8，所以第一轮只能发送 {} 字节：",
        client.peer_window, first_sent
    );

    for segment in first_batch {
        print_tcp_segment("   Client -> Server", &segment);
        let ack = server.receive(segment).unwrap().unwrap();
        print_tcp_segment("   Server -> Client", &ack);
        client.receive(ack).unwrap();
        println!(
            "   窗口滑动：send_base={}，next_seq={}，peer_rwnd={}",
            client.send_base, client.next_seq, client.peer_window
        );
    }

    let blocked = client.send_data(&data[first_sent..], 4).unwrap();
    println!(
        "Server 缓冲区已满：rwnd={}；剩余 4 字节发送结果={} 段（发送暂停）",
        server.rwnd,
        blocked.len()
    );

    let consumed = server.application_read(4);
    println!(
        "Server 应用读取 {:?}，空出 4 字节，rwnd={}",
        String::from_utf8_lossy(&consumed),
        server.rwnd
    );
    let window_update = server.window_update().unwrap();
    print_tcp_segment("   Server -> Client（窗口更新）", &window_update);
    client.receive(window_update).unwrap();

    let second_batch = client.send_data(&data[first_sent..], 4).unwrap();
    for segment in second_batch {
        print_tcp_segment("   Client -> Server", &segment);
        let ack = server.receive(segment).unwrap().unwrap();
        print_tcp_segment("   Server -> Client", &ack);
        client.receive(ack).unwrap();
    }
    println!(
        "12 字节全部确认：send_base={}，next_seq={}，未确认段={}\n",
        client.send_base,
        client.next_seq,
        client.unacked.len()
    );

    println!("--- 三、四次挥手 ---");
    let client_fin = client.close().unwrap();
    print_tcp_segment("1. Client -> Server", &client_fin);
    println!("   Client -> {:?}", client.state);

    let server_ack = server.receive(client_fin).unwrap().unwrap();
    print_tcp_segment("2. Server -> Client", &server_ack);
    println!("   Server -> {:?}（等待服务端应用 close）", server.state);
    client.receive(server_ack).unwrap();
    println!("   Client -> {:?}", client.state);

    let server_fin = server.close().unwrap();
    print_tcp_segment("3. Server -> Client", &server_fin);
    println!("   Server -> {:?}", server.state);

    let final_ack = client.receive(server_fin).unwrap().unwrap();
    print_tcp_segment("4. Client -> Server", &final_ack);
    server.receive(final_ack).unwrap();
    println!("   Client={:?}, Server={:?}", client.state, server.state);

    client.expire_time_wait().unwrap();
    println!("   2MSL 到期：Client -> {:?}\n", client.state);
    println!(
        "结论：TCP 用握手建立双方序号空间，用滑动窗口连续发送，用 rwnd 防止淹没接收方，最后用四次挥手独立关闭两个方向。\n"
    );
}

fn print_tcp_segment(label: &str, segment: &TcpSegment) {
    let data = if segment.payload.is_empty() {
        String::new()
    } else {
        format!(", data={:?}", String::from_utf8_lossy(&segment.payload))
    };
    println!(
        "{}: [{}] seq={}, ack={}, win={}{}",
        label,
        segment.flags(),
        segment.seq,
        segment.ack,
        segment.window,
        data
    );
}

// =============================================================================
// v0.6：Internet 诊断
// 目标：ARP、ICMP、ping 与 traceroute。ARP 从“LAN 辅助机制”升级为逐跳解析。
// =============================================================================
pub fn demo_v06_internet_diagnostics() {
    demo_v06_ping_same_lan();
    demo_v06_ping_across_router();
    demo_v06_traceroute();
}

// 场景一：同一 LAN 内 ping，观察 ARP + ICMP Echo。
fn demo_v06_ping_same_lan() {
    println!("========== v0.6：ICMP ping（同一 LAN） ==========");

    let netmask = Ipv4Addr { value: 0xFFFF_FF00 }; // /24
    let make_host = |name: &str, ip: Ipv4Addr, mac: MacAddr| -> Rc<Host> {
        let mut routes = RoutingTable::new();
        routes.add_direct_route(0, ip, netmask);
        Rc::new(Host::new(name, ip, netmask, routes, mac))
    };

    let alice_ip = Ipv4Addr { value: 0xC0A8_0102 }; // 192.168.1.2
    let bob_ip = Ipv4Addr { value: 0xC0A8_0103 }; // 192.168.1.3
    let alice = make_host("Alice", alice_ip, MacAddr::new([0x02, 0, 0, 0, 0, 2]));
    let bob = make_host("Bob", bob_ip, MacAddr::new([0x02, 0, 0, 0, 0, 3]));
    let mut switch = Switch::new();
    switch.connect(0, alice.clone());
    switch.connect(1, bob);

    alice.ping(bob_ip, 1, &mut switch).unwrap();
    println!("结论：Echo Request 和 Echo Reply 都经过 IP → ARP → Ethernet。\n");
}

// 场景二：跨 Router ping，以及 Time Exceeded / Destination Unreachable。
fn demo_v06_ping_across_router() {
    println!("========== v0.6：跨 Router ping 与 ICMP 错误 ==========");

    let mask = Ipv4Addr { value: 0xFFFF_FF00 };
    let alice_ip = Ipv4Addr { value: 0xC0A8_0102 }; // 192.168.1.2
    let left_gateway = Ipv4Addr { value: 0xC0A8_0101 }; // 192.168.1.1
    let right_gateway = Ipv4Addr { value: 0x0A00_0001 }; // 10.0.0.1
    let bob_ip = Ipv4Addr { value: 0x0A00_0002 }; // 10.0.0.2
    let alice_mac = MacAddr::new([0x02, 0, 0, 0, 1, 2]);
    let router_left_mac = MacAddr::new([0x02, 0, 0, 0, 1, 1]);
    let router_right_mac = MacAddr::new([0x02, 0, 0, 0, 2, 1]);
    let bob_mac = MacAddr::new([0x02, 0, 0, 0, 2, 2]);

    let mut alice_routes = RoutingTable::new();
    alice_routes.add_direct_route(0, alice_ip, mask);
    alice_routes.add_default_route(0, left_gateway);
    let alice = Host::new("Alice", alice_ip, mask, alice_routes, alice_mac);

    let mut bob_routes = RoutingTable::new();
    bob_routes.add_direct_route(0, bob_ip, mask);
    bob_routes.add_default_route(0, right_gateway);
    let bob = Host::new("Bob", bob_ip, mask, bob_routes, bob_mac);

    let left = Interface::new("left", left_gateway, mask, router_left_mac);
    let right = Interface::new("right", right_gateway, mask, router_right_mac);
    let mut router_routes = RoutingTable::new();
    router_routes.add_direct_route(0, left.ip, mask);
    router_routes.add_direct_route(1, right.ip, mask);
    let router = Router::new("R1", vec![left, right], router_routes);

    println!("ARP 预填：Alice→R1-left，R1-right→Bob；反向映射也已知。");
    println!("--- 场景一：Echo Request 跨 Router，Echo Reply 原路返回 ---");
    let request = alice.create_ping_packet(bob_ip, 1);
    let alice_next_hop = alice.next_hop(bob_ip).unwrap();
    println!(
        "Alice: dst={}，next-hop={}，Ethernet {} -> {}",
        bob_ip.to_dotted(),
        alice_next_hop.to_dotted(),
        alice_mac.to_string(),
        router_left_mac.to_string()
    );

    let forwarded_request = match router.receive_ip(0, request) {
        RouterAction::Forward {
            packet,
            next_hop,
            iface,
            src_mac,
        } => {
            println!(
                "R1: TTL 64 -> {}，route dst={}，out={}，next-hop={}",
                packet.ttl,
                packet.dst.to_dotted(),
                router.interfaces[iface].name,
                next_hop.to_dotted()
            );
            println!(
                "R1: Ethernet {} -> {}",
                src_mac.to_string(),
                bob_mac.to_string()
            );
            packet
        }
        RouterAction::Reply {
            packet,
            next_hop,
            iface,
            src_mac,
        } => panic!(
            "正常 ping 不应产生 Reply: src={}, next-hop={}, iface={}, mac={}",
            packet.src.to_dotted(),
            next_hop.to_dotted(),
            iface,
            src_mac.to_string()
        ),
        RouterAction::Drop { reason } => panic!("正常 ping 被丢弃: {:?}", reason),
    };

    let reply = bob
        .receive_ip(&forwarded_request)
        .expect("Bob 应创建 Echo Reply");
    println!(
        "Bob: Echo Request 到达，创建 Echo Reply；next-hop={}",
        bob.next_hop(alice_ip).unwrap().to_dotted()
    );

    let forwarded_reply = match router.receive_ip(1, reply) {
        RouterAction::Forward {
            packet,
            next_hop,
            iface,
            src_mac,
        } => {
            println!(
                "R1: Reply TTL 64 -> {}，out={}，next-hop={}",
                packet.ttl,
                router.interfaces[iface].name,
                next_hop.to_dotted()
            );
            println!(
                "R1: Ethernet {} -> {}",
                src_mac.to_string(),
                alice_mac.to_string()
            );
            packet
        }
        RouterAction::Reply {
            packet,
            next_hop,
            iface,
            src_mac,
        } => panic!(
            "Echo Reply 不应变成 Router Reply: src={}, next-hop={}, iface={}, mac={}",
            packet.src.to_dotted(),
            next_hop.to_dotted(),
            iface,
            src_mac.to_string()
        ),
        RouterAction::Drop { reason } => panic!("Echo Reply 被丢弃: {:?}", reason),
    };
    alice.receive_ip(&forwarded_reply);
    println!();

    println!("--- 场景二：TTL=1，在 R1 耗尽 ---");
    let mut ttl_probe = alice.create_ping_packet(bob_ip, 2);
    ttl_probe.ttl = 1;
    match router.receive_ip(0, ttl_probe) {
        RouterAction::Reply {
            packet,
            next_hop,
            iface,
            src_mac,
        } => {
            println!(
                "R1: TTL 耗尽，生成 ICMP Time Exceeded；out={}，next-hop={}，src-mac={}",
                router.interfaces[iface].name,
                next_hop.to_dotted(),
                src_mac.to_string()
            );
            alice.receive_ip(&packet);
        }
        RouterAction::Forward {
            packet,
            next_hop,
            iface,
            src_mac,
        } => panic!(
            "TTL=1 不应转发: dst={}, next-hop={}, iface={}, mac={}",
            packet.dst.to_dotted(),
            next_hop.to_dotted(),
            iface,
            src_mac.to_string()
        ),
        RouterAction::Drop { reason } => panic!("无法回送 Time Exceeded: {:?}", reason),
    }
    println!();

    println!("--- 场景三：R1 没有到 172.16.0.2 的路由 ---");
    let unreachable = Ipv4Addr { value: 0xAC10_0002 };
    let request = alice.create_ping_packet(unreachable, 3);
    match router.receive_ip(0, request) {
        RouterAction::Reply {
            packet,
            next_hop,
            iface,
            src_mac,
        } => {
            println!(
                "R1: 无目的路由，生成 ICMP Destination Unreachable；out={}，next-hop={}，src-mac={}",
                router.interfaces[iface].name,
                next_hop.to_dotted(),
                src_mac.to_string()
            );
            alice.receive_ip(&packet);
        }
        RouterAction::Forward {
            packet,
            next_hop,
            iface,
            src_mac,
        } => panic!(
            "无路由不应转发: dst={}, next-hop={}, iface={}, mac={}",
            packet.dst.to_dotted(),
            next_hop.to_dotted(),
            iface,
            src_mac.to_string()
        ),
        RouterAction::Drop { reason } => panic!("无法回送 Destination Unreachable: {:?}", reason),
    }
    println!();
}

// 场景三：逐步增加 TTL，由 ICMP 响应反推出路径。
fn demo_v06_traceroute() {
    println!("========== v0.6：traceroute ==========");
    println!("拓扑：Alice -- R1 -- R2 -- R3 -- Bob");

    let lan_mask = Ipv4Addr { value: 0xFFFF_FF00 }; // /24
    let link_mask = Ipv4Addr { value: 0xFFFF_FFFC }; // /30 点到点链路
    let alice_ip = Ipv4Addr { value: 0xC0A8_0102 }; // 192.168.1.2
    let bob_ip = Ipv4Addr { value: 0xAC10_0002 }; // 172.16.0.2
    let alice = Host::new(
        "Alice",
        alice_ip,
        lan_mask,
        RoutingTable::new(),
        MacAddr::new([0x02, 0, 0, 0, 1, 2]),
    );
    let bob = Host::new(
        "Bob",
        bob_ip,
        lan_mask,
        RoutingTable::new(),
        MacAddr::new([0x02, 0, 0, 0, 4, 2]),
    );

    // R1: 192.168.1.0/24 <-> 10.0.12.0/30
    let r1_left = Interface::new(
        "lan-a",
        Ipv4Addr { value: 0xC0A8_0101 },
        lan_mask,
        MacAddr::new([0x02, 0, 0, 0, 1, 1]),
    );
    let r1_right = Interface::new(
        "to-r2",
        Ipv4Addr { value: 0x0A00_0C01 },
        link_mask,
        MacAddr::new([0x02, 0, 0, 0, 12, 1]),
    );
    let mut r1_routes = RoutingTable::new();
    r1_routes.add_direct_route(0, r1_left.ip, lan_mask);
    r1_routes.add_direct_route(1, r1_right.ip, link_mask);
    r1_routes.add_route(
        Ipv4Addr { value: 0xAC10_0000 },
        24,
        Ipv4Addr { value: 0x0A00_0C02 },
        1,
    );
    let r1 = Router::new("R1", vec![r1_left, r1_right], r1_routes);

    // R2: 10.0.12.0/30 <-> 10.0.23.0/30
    let r2_left = Interface::new(
        "to-r1",
        Ipv4Addr { value: 0x0A00_0C02 },
        link_mask,
        MacAddr::new([0x02, 0, 0, 0, 12, 2]),
    );
    let r2_right = Interface::new(
        "to-r3",
        Ipv4Addr { value: 0x0A00_1701 },
        link_mask,
        MacAddr::new([0x02, 0, 0, 0, 23, 1]),
    );
    let mut r2_routes = RoutingTable::new();
    r2_routes.add_direct_route(0, r2_left.ip, link_mask);
    r2_routes.add_direct_route(1, r2_right.ip, link_mask);
    r2_routes.add_route(
        Ipv4Addr { value: 0xC0A8_0100 },
        24,
        Ipv4Addr { value: 0x0A00_0C01 },
        0,
    );
    r2_routes.add_route(
        Ipv4Addr { value: 0xAC10_0000 },
        24,
        Ipv4Addr { value: 0x0A00_1702 },
        1,
    );
    let r2 = Router::new("R2", vec![r2_left, r2_right], r2_routes);

    // R3: 10.0.23.0/30 <-> 172.16.0.0/24
    let r3_left = Interface::new(
        "to-r2",
        Ipv4Addr { value: 0x0A00_1702 },
        link_mask,
        MacAddr::new([0x02, 0, 0, 0, 23, 2]),
    );
    let r3_right = Interface::new(
        "lan-b",
        Ipv4Addr { value: 0xAC10_0001 },
        lan_mask,
        MacAddr::new([0x02, 0, 0, 0, 4, 1]),
    );
    let mut r3_routes = RoutingTable::new();
    r3_routes.add_direct_route(0, r3_left.ip, link_mask);
    r3_routes.add_direct_route(1, r3_right.ip, lan_mask);
    r3_routes.add_route(
        Ipv4Addr { value: 0xC0A8_0100 },
        24,
        Ipv4Addr { value: 0x0A00_1701 },
        0,
    );
    let r3 = Router::new("R3", vec![r3_left, r3_right], r3_routes);

    let path = [
        TraceRouter {
            router: &r1,
            incoming_iface: 0,
        },
        TraceRouter {
            router: &r2,
            incoming_iface: 0,
        },
        TraceRouter {
            router: &r3,
            incoming_iface: 0,
        },
    ];
    println!("traceroute to {}, max_hops=8", bob_ip.to_dotted());
    for hop in trace_route(&alice, &bob, bob_ip, &path, 8) {
        let responder = hop
            .responder
            .map(|ip| ip.to_dotted())
            .unwrap_or_else(|| "*".to_string());
        match hop.outcome {
            TraceOutcome::TimeExceeded => println!("{:>2}  {}  Time Exceeded", hop.ttl, responder),
            TraceOutcome::ReachedDestination => {
                println!("{:>2}  {}  Echo Reply（到达目标）", hop.ttl, responder)
            }
            TraceOutcome::DestinationUnreachable => {
                println!("{:>2}  {}  Destination Unreachable", hop.ttl, responder)
            }
            TraceOutcome::Dropped(reason) => println!("{:>2}  *  Drop: {:?}", hop.ttl, reason),
            TraceOutcome::Timeout => println!("{:>2}  *  Timeout", hop.ttl),
        }
    }
    println!(
        "结论：traceroute 不需要新协议；它只是重复发送不同 TTL 的探测包，并读取 ICMP 响应。\n"
    );
}

// =============================================================================
// v0.7：应用层
// 目标：DNS over UDP + Mini HTTP Client/Server over TCP。
// =============================================================================
pub fn demo_v07_application_layer() {
    println!("========== v0.7：Application Layer（DNS + Mini HTTP） ==========");
    let client_ip = Ipv4Addr { value: 0xC0A8_0102 }; // 192.168.1.2
    let web_server_ip = Ipv4Addr { value: 0x0A00_0008 }; // 10.0.0.8

    println!("\n--- Part 1：DNS 层次查询、UDP 封装与缓存 ---");
    let root = DnsServer::new(
        "Root DNS",
        Ipv4Addr { value: 0xC000_0201 },
        vec![
            DnsRecord::ns("com", "a.gtld.test", 300),
            DnsRecord::a("a.gtld.test", Ipv4Addr { value: 0xC000_0202 }, 300),
        ],
    );
    let tld = DnsServer::new(
        ".com TLD DNS",
        Ipv4Addr { value: 0xC000_0202 },
        vec![
            DnsRecord::ns("tinynet.com", "ns.tinynet.com", 300),
            DnsRecord::a("ns.tinynet.com", Ipv4Addr { value: 0xC000_0203 }, 300),
        ],
    );
    let authoritative = DnsServer::new(
        "tinynet.com Authoritative DNS",
        Ipv4Addr { value: 0xC000_0203 },
        vec![DnsRecord::a("www.tinynet.com", web_server_ip, 300)],
    );
    let servers = [&root, &tld, &authoritative];
    let mut resolver = DnsResolver::new(client_ip, 53_000);

    println!("[Resolver] www.tinynet.com A?\n[Cache] MISS");
    let first = resolver.resolve("www.tinynet.com", &servers).unwrap();
    for exchange in &first.exchanges {
        print_dns_exchange(exchange);
    }
    println!(
        "[Cache] store www.tinynet.com -> {} TTL={}",
        first.ip.to_dotted(),
        first.ttl
    );

    resolver.tick(); // 模拟 1 秒过去，DNS TTL 300 → 299。
    let cached_after_tick = resolver.cached("www.tinynet.com").unwrap();
    println!(
        "[Time] tick：DNS cache TTL {} -> {}",
        first.ttl, cached_after_tick.ttl
    );
    let second = resolver.resolve("www.tinynet.com", &servers).unwrap();
    println!("\n[Resolver] 再次查询 www.tinynet.com");
    println!(
        "[Cache] {} -> {} TTL={}（没有发送 UDP 包）",
        if second.cache_hit { "HIT" } else { "MISS" },
        second.ip.to_dotted(),
        second.ttl
    );

    println!("\n--- Part 2：HTTP over TCP ---");
    println!("DNS 结果：www.tinynet.com -> {}", second.ip.to_dotted());
    let mut http_server = HttpServer::new("www.tinynet.com");
    http_server.add_resource("/index.html", "<h1>TinyNet</h1>");
    http_server.add_resource("/hello.txt", "hello network");
    let mut session = HttpSession::new(http_server, 50_000);
    let handshake = session.connect().unwrap();
    for (index, segment) in handshake.iter().enumerate() {
        println!(
            "TCP {}: [{}] seq={} ack={}",
            index + 1,
            segment.flags(),
            segment.seq,
            segment.ack
        );
    }
    println!(
        "TCP: Client={:?}, Server={:?}",
        session.tcp_client.state, session.tcp_server.state
    );

    for path in ["/index.html", "/not-found", "/hello.txt"] {
        let exchange = session.get(path).unwrap();
        println!(
            "\n[HTTP Request #{} / same TCP connection]",
            session.request_count
        );
        print!("{}", String::from_utf8_lossy(&exchange.request.to_bytes()));
        println!(
            "[TCP] request bytes in {} segment(s)",
            exchange.request_segments.len()
        );
        println!("[HTTP Response]");
        print!("{}", String::from_utf8_lossy(&exchange.response.to_bytes()));
        println!(
            "\n[TCP] response bytes in {} segment(s)",
            exchange.response_segments.len()
        );
    }

    println!("\n--- Part 3：HTTP/1.1 持久连接结论 ---");
    println!("TCP handshakes = {}", session.handshake_count);
    println!("HTTP requests = {}", session.request_count);
    println!("三个 GET 共用同一个 ESTABLISHED 连接，没有重新三次握手。");
    session.close().unwrap();
    println!(
        "TCP close: Client={:?}, Server={:?}",
        session.tcp_client.state, session.tcp_server.state
    );
    println!("\n结论：URL → DNS/UDP/IP → Server IP → TCP → HTTP 字节流，v0.7 完成。\n");
}

fn print_dns_exchange(exchange: &DnsExchange) {
    let IpPayload::Udp(query_udp) = &exchange.query.payload else {
        unreachable!()
    };
    let UdpPayload::Dns(query) = &query_udp.payload;
    let question = &query.questions[0];
    println!(
        "\n-> {} ({})",
        exchange.server_name,
        exchange.query.dst.to_dotted()
    );
    println!(
        "   [DNS] Query ID={} {} {:?}?",
        query.id, question.name, question.record_type
    );
    println!("   [UDP] {} -> {}", query_udp.src_port, query_udp.dst_port);
    println!(
        "   [IP] {} -> {}",
        exchange.query.src.to_dotted(),
        exchange.query.dst.to_dotted()
    );

    let IpPayload::Udp(response_udp) = &exchange.response.payload else {
        unreachable!()
    };
    let UdpPayload::Dns(response) = &response_udp.payload;
    if let Some(answer) = response.answers.first() {
        if let DnsRecordData::A(ip) = answer.data {
            println!(
                "<- [DNS] Answer {} A {} TTL={}",
                answer.name,
                ip.to_dotted(),
                answer.ttl
            );
        }
    } else if let Some(authority) = response.authorities.first() {
        if let DnsRecordData::Ns(name_server) = &authority.data {
            let glue = response
                .additionals
                .iter()
                .find_map(|record| match record.data {
                    DnsRecordData::A(ip) => Some(ip.to_dotted()),
                    _ => None,
                })
                .unwrap_or_else(|| "no glue".to_string());
            println!(
                "<- [DNS] Referral: {} NS {} ({})",
                authority.name, name_server, glue
            );
        }
    }
    println!(
        "   [UDP] {} -> {}",
        response_udp.src_port, response_udp.dst_port
    );
}

// =============================================================================
// v1.0：Mini Internet
// 目标：把之前的协议放进同一个事件驱动网络，让 Application 跨多个 Router 通信。
// 正式验收是 Browser；Chat 用来证明同一网络可以继续承载新的 Application。
// =============================================================================
pub fn demo_v10_mini_internet() {
    demo_v10_network_engine();
    demo_v10_automatic_multi_router();
    demo_v10_dynamic_arp_dns();
    demo_v10_tcp_http_retransmission();
    demo_v10_browser_open();
    demo_v10_chat();
}

// 检查点 1：Link + EventQueue，只验证帧按延迟到达对端。
fn demo_v10_network_engine() {
    println!("========== v1.0 检查点 1：Network Engine ==========");
    let mut network = Network::new();
    let browser = network.add_node("Browser-A", NodeKind::Host, 1);
    let r1 = network.add_node("R1", NodeKind::Router, 2);
    let browser_eth0 = Endpoint {
        node: browser,
        interface: 0,
    };
    let r1_eth0 = Endpoint {
        node: r1,
        interface: 0,
    };
    network.connect(browser_eth0, r1_eth0, 12, 0).unwrap();

    println!("[Topology] Browser-A:eth0 ===(delay 12ms)===> R1:eth0");
    let frame = crate::packet::EthernetFrame {
        src: MacAddr::new([0x02, 0, 0, 0, 1, 2]),
        dst: MacAddr::new([0x02, 0, 0, 0, 1, 1]),
        payload: crate::packet::EthernetPayload::Ip(IpPacket {
            src: Ipv4Addr { value: 0xC0A8_0102 },
            dst: Ipv4Addr { value: 0x0A00_0302 },
            ttl: 64,
            payload: IpPayload::Data("first v1.0 frame".to_string()),
        }),
    };
    match network.send_frame(browser_eth0, frame).unwrap() {
        SendDisposition::Scheduled {
            arrival_time_ms, ..
        } => {
            println!(
                "[t=0ms] Browser-A 从 eth0 发帧；排队等待，预计 t={}ms 到达",
                arrival_time_ms
            )
        }
        SendDisposition::Dropped { .. } => unreachable!(),
    }
    println!("[EventQueue] pending={}", network.pending_events());

    for timed in network.run() {
        match timed.event {
            NetworkEvent::FrameArrival { from, to, frame } => {
                let from_name = &network.node(from.node).unwrap().name;
                let to_name = &network.node(to.node).unwrap().name;
                println!(
                    "[t={}ms] FrameArrival: {}:eth{} -> {}:eth{}",
                    timed.time_ms, from_name, from.interface, to_name, to.interface
                );
                println!(
                    "          Ethernet {} -> {}",
                    frame.src.to_string(),
                    frame.dst.to_string()
                );
            }
            NetworkEvent::Timer { .. } => unreachable!("检查点 1 没有注册协议定时器"),
        }
    }
    println!("这一阶段 Engine 只搬运帧；下一步才让 R1 收包、查路由并自动从 eth1 继续发送。\n");
}

// 检查点 2：Host/Router 自动处理事件，Demo 不再逐台调用 Router。
fn demo_v10_automatic_multi_router() {
    println!("========== v1.0 检查点 2：Automatic Multi-Router Forwarding ==========");
    println!("拓扑：App-A -- R1 -- R2 -- R3 -- App-B（每条 Link delay=5ms）");

    let lan_mask = Ipv4Addr { value: 0xFFFF_FF00 };
    let link_mask = Ipv4Addr { value: 0xFFFF_FFFC };
    let a_ip = Ipv4Addr { value: 0xC0A8_0102 };
    let b_ip = Ipv4Addr { value: 0x0A00_0302 };
    let a_mac = MacAddr::new([0x02, 0, 0, 0, 1, 2]);
    let b_mac = MacAddr::new([0x02, 0, 0, 0, 4, 2]);

    let mut a_routes = RoutingTable::new();
    a_routes.add_direct_route(0, a_ip, lan_mask);
    a_routes.add_default_route(0, Ipv4Addr { value: 0xC0A8_0101 });
    let app_a = Host::new("App-A", a_ip, lan_mask, a_routes, a_mac);
    let mut b_routes = RoutingTable::new();
    b_routes.add_direct_route(0, b_ip, lan_mask);
    b_routes.add_default_route(0, Ipv4Addr { value: 0x0A00_0301 });
    let app_b = Host::new("App-B", b_ip, lan_mask, b_routes, b_mac);

    let r1_left_mac = MacAddr::new([0x02, 0, 0, 0, 1, 1]);
    let r1_right_mac = MacAddr::new([0x02, 0, 0, 0, 12, 1]);
    let r2_left_mac = MacAddr::new([0x02, 0, 0, 0, 12, 2]);
    let r2_right_mac = MacAddr::new([0x02, 0, 0, 0, 23, 1]);
    let r3_left_mac = MacAddr::new([0x02, 0, 0, 0, 23, 2]);
    let r3_right_mac = MacAddr::new([0x02, 0, 0, 0, 4, 1]);

    let r1_left = Interface::new(
        "lan-a",
        Ipv4Addr { value: 0xC0A8_0101 },
        lan_mask,
        r1_left_mac,
    );
    let r1_right = Interface::new(
        "to-r2",
        Ipv4Addr { value: 0x0A00_0C01 },
        link_mask,
        r1_right_mac,
    );
    let mut r1_routes = RoutingTable::new();
    r1_routes.add_direct_route(0, r1_left.ip, lan_mask);
    r1_routes.add_direct_route(1, r1_right.ip, link_mask);
    r1_routes.add_route(b_ip, 24, Ipv4Addr { value: 0x0A00_0C02 }, 1);
    let r1 = Router::new("R1", vec![r1_left, r1_right], r1_routes);

    let r2_left = Interface::new(
        "to-r1",
        Ipv4Addr { value: 0x0A00_0C02 },
        link_mask,
        r2_left_mac,
    );
    let r2_right = Interface::new(
        "to-r3",
        Ipv4Addr { value: 0x0A00_1701 },
        link_mask,
        r2_right_mac,
    );
    let mut r2_routes = RoutingTable::new();
    r2_routes.add_direct_route(0, r2_left.ip, link_mask);
    r2_routes.add_direct_route(1, r2_right.ip, link_mask);
    r2_routes.add_route(a_ip, 24, Ipv4Addr { value: 0x0A00_0C01 }, 0);
    r2_routes.add_route(b_ip, 24, Ipv4Addr { value: 0x0A00_1702 }, 1);
    let r2 = Router::new("R2", vec![r2_left, r2_right], r2_routes);

    let r3_left = Interface::new(
        "to-r2",
        Ipv4Addr { value: 0x0A00_1702 },
        link_mask,
        r3_left_mac,
    );
    let r3_right = Interface::new(
        "lan-b",
        Ipv4Addr { value: 0x0A00_0301 },
        lan_mask,
        r3_right_mac,
    );
    let mut r3_routes = RoutingTable::new();
    r3_routes.add_direct_route(0, r3_left.ip, link_mask);
    r3_routes.add_direct_route(1, r3_right.ip, lan_mask);
    r3_routes.add_route(a_ip, 24, Ipv4Addr { value: 0x0A00_1701 }, 0);
    let r3 = Router::new("R3", vec![r3_left, r3_right], r3_routes);

    let mut internet = MiniInternet::new();
    let a = internet.add_host(app_a);
    let r1 = internet.add_router(r1);
    let r2 = internet.add_router(r2);
    let r3 = internet.add_router(r3);
    let b = internet.add_host(app_b);
    for (left, right) in [
        (
            Endpoint {
                node: a,
                interface: 0,
            },
            Endpoint {
                node: r1,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r1,
                interface: 1,
            },
            Endpoint {
                node: r2,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r2,
                interface: 1,
            },
            Endpoint {
                node: r3,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r3,
                interface: 1,
            },
            Endpoint {
                node: b,
                interface: 0,
            },
        ),
    ] {
        internet.connect(left, right, 5, 0).unwrap();
    }

    println!(
        "[APP] App-A 只请求 send(dst={})；不知道中间有几台 Router",
        b_ip.to_dotted()
    );
    internet
        .send_ip(
            a,
            IpPacket {
                src: a_ip,
                dst: b_ip,
                ttl: 64,
                payload: IpPayload::Data("Hello across the Mini Internet".to_string()),
            },
        )
        .unwrap();
    internet.run().unwrap();

    for trace in &internet.trace {
        match trace {
            InternetTrace::FrameArrived {
                time_ms,
                from,
                to,
                src_mac,
                dst_mac,
            } => println!(
                "[t={:>2}ms] L2 {}:eth{} -> {}:eth{}  {} -> {}",
                time_ms,
                internet.node_name(from.node),
                from.interface,
                internet.node_name(to.node),
                to.interface,
                src_mac.to_string(),
                dst_mac.to_string()
            ),
            InternetTrace::RouterForwarded {
                time_ms,
                node,
                incoming_iface,
                outgoing_iface,
                next_hop,
                ttl,
            } => println!(
                "[t={:>2}ms]      [IP] {} recv eth{}: TTL→{}, route next-hop={}, send eth{}",
                time_ms,
                internet.node_name(*node),
                incoming_iface,
                ttl,
                next_hop.to_dotted(),
                outgoing_iface
            ),
            InternetTrace::HostReceived {
                time_ms,
                node,
                packet,
            } => println!(
                "[t={:>2}ms] [APP] {} received IP {} -> {}, TTL={}",
                time_ms,
                internet.node_name(*node),
                packet.src.to_dotted(),
                packet.dst.to_dotted(),
                packet.ttl
            ),
            _ => {}
        }
    }
    let delivered = internet.received_packets(b).unwrap();
    println!(
        "验收：App-B inbox={}，最终 TTL={}；demo 没有调用 R1/R2/R3。\n",
        delivered.len(),
        delivered[0].ttl
    );
}

// 检查点 3：动态 ARP、UDP 端口分用与跨路由 DNS。
fn demo_v10_dynamic_arp_dns() {
    println!("========== v1.0 检查点 3：Dynamic ARP + DNS over UDP ==========");
    println!("拓扑：Browser -- R1 -- R2 -- R3 -- DNS（所有 ARP Cache 初始为空）");

    let lan_mask = Ipv4Addr { value: 0xFFFF_FF00 };
    let link_mask = Ipv4Addr { value: 0xFFFF_FFFC };
    let browser_ip = Ipv4Addr { value: 0xC0A8_0102 };
    let dns_ip = Ipv4Addr { value: 0x0A00_0302 };
    let answer_ip = Ipv4Addr { value: 0x0A00_0363 };

    let mut browser_routes = RoutingTable::new();
    browser_routes.add_direct_route(0, browser_ip, lan_mask);
    browser_routes.add_default_route(0, Ipv4Addr { value: 0xC0A8_0101 });
    let browser_host = Host::new(
        "Browser",
        browser_ip,
        lan_mask,
        browser_routes,
        MacAddr::new([2, 0, 0, 0, 1, 2]),
    );
    let mut dns_routes = RoutingTable::new();
    dns_routes.add_direct_route(0, dns_ip, lan_mask);
    dns_routes.add_default_route(0, Ipv4Addr { value: 0x0A00_0301 });
    let dns_host = Host::new(
        "DNS",
        dns_ip,
        lan_mask,
        dns_routes,
        MacAddr::new([2, 0, 0, 0, 4, 2]),
    );

    let mut r1_routes = RoutingTable::new();
    r1_routes.add_direct_route(0, Ipv4Addr { value: 0xC0A8_0101 }, lan_mask);
    r1_routes.add_direct_route(1, Ipv4Addr { value: 0x0A00_0C01 }, link_mask);
    r1_routes.add_route(
        Ipv4Addr { value: 0x0A00_0300 },
        24,
        Ipv4Addr { value: 0x0A00_0C02 },
        1,
    );
    let r1 = Router::new(
        "R1",
        vec![
            Interface::new(
                "lan-browser",
                Ipv4Addr { value: 0xC0A8_0101 },
                lan_mask,
                MacAddr::new([2, 0, 0, 0, 1, 1]),
            ),
            Interface::new(
                "to-r2",
                Ipv4Addr { value: 0x0A00_0C01 },
                link_mask,
                MacAddr::new([2, 0, 0, 0, 12, 1]),
            ),
        ],
        r1_routes,
    );

    let mut r2_routes = RoutingTable::new();
    r2_routes.add_direct_route(0, Ipv4Addr { value: 0x0A00_0C02 }, link_mask);
    r2_routes.add_direct_route(1, Ipv4Addr { value: 0x0A00_1701 }, link_mask);
    r2_routes.add_route(
        Ipv4Addr { value: 0xC0A8_0100 },
        24,
        Ipv4Addr { value: 0x0A00_0C01 },
        0,
    );
    r2_routes.add_route(
        Ipv4Addr { value: 0x0A00_0300 },
        24,
        Ipv4Addr { value: 0x0A00_1702 },
        1,
    );
    let r2 = Router::new(
        "R2",
        vec![
            Interface::new(
                "to-r1",
                Ipv4Addr { value: 0x0A00_0C02 },
                link_mask,
                MacAddr::new([2, 0, 0, 0, 12, 2]),
            ),
            Interface::new(
                "to-r3",
                Ipv4Addr { value: 0x0A00_1701 },
                link_mask,
                MacAddr::new([2, 0, 0, 0, 23, 1]),
            ),
        ],
        r2_routes,
    );

    let mut r3_routes = RoutingTable::new();
    r3_routes.add_direct_route(0, Ipv4Addr { value: 0x0A00_1702 }, link_mask);
    r3_routes.add_direct_route(1, Ipv4Addr { value: 0x0A00_0301 }, lan_mask);
    r3_routes.add_route(
        Ipv4Addr { value: 0xC0A8_0100 },
        24,
        Ipv4Addr { value: 0x0A00_1701 },
        0,
    );
    let r3 = Router::new(
        "R3",
        vec![
            Interface::new(
                "to-r2",
                Ipv4Addr { value: 0x0A00_1702 },
                link_mask,
                MacAddr::new([2, 0, 0, 0, 23, 2]),
            ),
            Interface::new(
                "lan-dns",
                Ipv4Addr { value: 0x0A00_0301 },
                lan_mask,
                MacAddr::new([2, 0, 0, 0, 4, 1]),
            ),
        ],
        r3_routes,
    );

    let mut internet = MiniInternet::new();
    let browser = internet.add_host(browser_host);
    let r1 = internet.add_router(r1);
    let r2 = internet.add_router(r2);
    let r3 = internet.add_router(r3);
    let dns = internet.add_host(dns_host);
    for (left, right) in [
        (
            Endpoint {
                node: browser,
                interface: 0,
            },
            Endpoint {
                node: r1,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r1,
                interface: 1,
            },
            Endpoint {
                node: r2,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r2,
                interface: 1,
            },
            Endpoint {
                node: r3,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r3,
                interface: 1,
            },
            Endpoint {
                node: dns,
                interface: 0,
            },
        ),
    ] {
        internet.connect(left, right, 5, 0).unwrap();
    }
    internet
        .bind_dns_server(
            dns,
            DnsServer::new(
                "ns.tinynet.com",
                dns_ip,
                vec![DnsRecord::a("www.tinynet.com", answer_ip, 300)],
            ),
        )
        .unwrap();

    println!(
        "[APP] Browser: UDP 53000 → {}:53，查询 www.tinynet.com",
        dns_ip.to_dotted()
    );
    internet
        .send_udp(
            browser,
            dns_ip,
            UdpDatagram {
                src_port: 53_000,
                dst_port: DNS_PORT,
                payload: UdpPayload::Dns(DnsMessage::query(
                    100,
                    "www.tinynet.com",
                    DnsRecordType::A,
                )),
            },
        )
        .unwrap();
    internet.run().unwrap();

    for event in &internet.trace {
        match event {
            InternetTrace::ArpRequest {
                time_ms,
                node,
                interface,
                target_ip,
            } => println!(
                "[t={:>3}ms] [ARP] {}:eth{} Who has {}?",
                time_ms,
                internet.node_name(*node),
                interface,
                target_ip.to_dotted()
            ),
            InternetTrace::ArpReply {
                time_ms,
                node,
                interface,
                target_ip,
            } => println!(
                "[t={:>3}ms] [ARP] {}:eth{} replies to {}",
                time_ms,
                internet.node_name(*node),
                interface,
                target_ip.to_dotted()
            ),
            InternetTrace::UdpDelivered {
                time_ms,
                node,
                src_port,
                dst_port,
            } => println!(
                "[t={:>3}ms] [UDP] {} demux {} → port {}",
                time_ms,
                internet.node_name(*node),
                src_port,
                dst_port
            ),
            InternetTrace::DnsAnswered {
                time_ms,
                node,
                client,
                query_id,
            } => println!(
                "[t={:>3}ms] [DNS] {} answered query #{} for {}",
                time_ms,
                internet.node_name(*node),
                query_id,
                client.to_dotted()
            ),
            _ => {}
        }
    }

    let responses = internet.udp_datagrams(browser, 53_000).unwrap();
    let UdpPayload::Dns(answer) = &responses[0].1.payload;
    let DnsRecordData::A(resolved_ip) = answer.answers[0].data else {
        unreachable!()
    };
    println!(
        "验收：UDP/53000 收到 DNS Response，www.tinynet.com → {}；全程未预填 ARP。\n",
        resolved_ip.to_dotted()
    );
}

// 检查点 4：TCP/HTTP 跨路由，并在 Link 丢包后触发 RTO 重传。
fn demo_v10_tcp_http_retransmission() {
    println!("========== v1.0 检查点 4：HTTP over Lossy TCP ==========");
    println!("拓扑：Browser -- R1 -- R2 -- R3 -- Web Server");
    let (mut internet, browser, web, r1, _, web_ip) =
        build_v10_three_router_topology("Browser", "Web");
    let client_port = 50_000;

    let mut server = HttpServer::new("www.tinynet.com");
    server.add_resource("/index.html", "<h1>Hello from the Mini Internet</h1>");
    internet.bind_http_server(web, 80, server).unwrap();

    println!("\n--- 1. TCP 三次握手（真正穿过 R1/R2/R3）---");
    internet
        .tcp_connect(browser, client_port, web_ip, 80)
        .unwrap();
    internet.run().unwrap();
    print_v10_tcp_trace(&internet, 0);
    println!(
        "连接状态：Client={:?}, Server={:?}",
        internet.tcp_state(browser, client_port).unwrap(),
        internet.tcp_state(web, 80).unwrap()
    );

    println!("\n--- 2. HTTP GET；故意丢弃 R1→R2 的请求帧 ---");
    let trace_start = internet.trace.len();
    internet
        .network
        .drop_next_frame_from(Endpoint {
            node: r1,
            interface: 1,
        })
        .unwrap();
    internet
        .http_get(browser, client_port, "www.tinynet.com", "/index.html")
        .unwrap();
    internet.run().unwrap();
    print_v10_tcp_trace(&internet, trace_start);
    let response = internet.read_http_response(browser, client_port).unwrap();
    println!(
        "[Browser] HTTP/1.1 {} {}，body={:?}",
        response.status_code, response.reason, response.body
    );

    println!("\n--- 3. TCP 四次挥手 ---");
    let trace_start = internet.trace.len();
    internet.tcp_close(browser, client_port).unwrap();
    internet.run().unwrap();
    print_v10_tcp_trace(&internet, trace_start);
    println!(
        "2MSL 前：Client={:?}, Server={:?}",
        internet.tcp_state(browser, client_port).unwrap(),
        internet.tcp_state(web, 80).unwrap()
    );
    internet.expire_tcp_time_wait(browser, client_port).unwrap();
    println!(
        "2MSL 后：Client={:?}, Server={:?}",
        internet.tcp_state(browser, client_port).unwrap(),
        internet.tcp_state(web, 80).unwrap()
    );
    println!("验收：握手、HTTP 字节、ACK、RTO 重传与挥手都经过统一 EventQueue。\n");
}

fn print_v10_tcp_trace(internet: &MiniInternet, start: usize) {
    for event in &internet.trace[start..] {
        match event {
            InternetTrace::TcpSent {
                time_ms,
                node,
                segment,
                retransmission,
                ..
            } => println!(
                "[t={:>3}ms] [TCP] {} send [{}] seq={} ack={} bytes={}{}",
                time_ms,
                internet.node_name(*node),
                segment.flags(),
                segment.seq,
                segment.ack,
                segment.payload.len(),
                if *retransmission { "  RETRANSMIT" } else { "" }
            ),
            InternetTrace::LinkDropped { time_ms, from, .. } => println!(
                "[t={:>3}ms] [LINK] DROP {}:eth{} 的帧",
                time_ms,
                internet.node_name(from.node),
                from.interface
            ),
            InternetTrace::TcpTimeout {
                time_ms, node, seq, ..
            } => println!(
                "[t={:>3}ms] [RTO] {} timeout seq={}",
                time_ms,
                internet.node_name(*node),
                seq
            ),
            InternetTrace::TcpStateChanged {
                time_ms,
                node,
                old,
                new,
                ..
            } => println!(
                "[t={:>3}ms] [TCP] {} {:?} → {:?}",
                time_ms,
                internet.node_name(*node),
                old,
                new
            ),
            InternetTrace::HttpHandled {
                time_ms,
                node,
                path,
                status_code,
            } => println!(
                "[t={:>3}ms] [HTTP] {} GET {} → {}",
                time_ms,
                internet.node_name(*node),
                path,
                status_code
            ),
            _ => {}
        }
    }
}

// 附加 Demo：小明 ↔ 小红 Chat，展示如何复用 MiniInternet 增加新应用。
fn demo_v10_chat() {
    println!("========== v1.0：小明 ↔ 小红 Chat ==========");
    println!("拓扑：小明 -- R1 -- R2 -- R3 -- 小红");
    println!("应用只看见联系人和 TCP 连接，不知道中间 Router 与 MAC。\n");

    let (mut internet, xiaoming_node, xiaohong_node, _, r2, xiaohong_ip) =
        build_v10_three_router_topology("小明", "小红");
    let mut xiaoming = ChatApp::new("小明", xiaoming_node, 50_000);
    let mut xiaohong = ChatApp::new("小红", xiaohong_node, 7_000);

    xiaohong.listen(&mut internet).unwrap();
    xiaoming
        .connect(&mut internet, xiaohong_ip, xiaohong.local_port)
        .unwrap();
    internet.run().unwrap();
    println!(
        "[Chat] 会话已连接：小明={:?}，小红={:?}",
        internet.tcp_state(xiaoming_node, 50_000).unwrap(),
        internet.tcp_state(xiaohong_node, 7_000).unwrap()
    );

    // ARP 和握手已经完成。现在只丢 R2→R3 的下一帧，稳定命中第一条聊天消息。
    let trace_start = internet.trace.len();
    internet
        .network
        .drop_next_frame_from(Endpoint {
            node: r2,
            interface: 1,
        })
        .unwrap();
    let first_id = xiaoming
        .send(&mut internet, "小红，你好！这条消息能穿过三个路由器吗？")
        .unwrap();
    println!("[小明] #{first_id} 发送中…");
    internet.run().unwrap();
    print_chat_reliability_trace(&internet, trace_start);
    let first = xiaohong.receive(&mut internet).unwrap().unwrap();
    // 即使底层发生重传，应用缓冲区也只交付一次消息。
    assert!(xiaohong.receive(&mut internet).unwrap().is_none());
    println!("[小明] #{first_id} ✓ 已送达\n");

    let reply_id = xiaohong
        .send(&mut internet, "收到了！我只看到一条，没有重复消息。")
        .unwrap();
    internet.run().unwrap();
    let reply = xiaoming.receive(&mut internet).unwrap().unwrap();

    let last_id = xiaoming
        .send(&mut internet, "太好了，TinyNet 真的连起来了。")
        .unwrap();
    internet.run().unwrap();
    let last = xiaohong.receive(&mut internet).unwrap().unwrap();

    println!("┌──────────────── TinyChat ────────────────┐");
    println!("│ 小明 #{:<2}  {:<28} │", first.id, first.text);
    println!("│          小红 #{:<2}  {:<22} │", reply.id, reply.text);
    println!("│ 小明 #{:<2}  {:<28} │", last.id, last.text);
    println!("└─────────────────────────────────────────┘");
    println!("消息状态：#{reply_id} ✓  #{last_id} ✓");

    xiaoming.close(&mut internet).unwrap();
    internet.run().unwrap();
    internet
        .expire_tcp_time_wait(xiaoming_node, xiaoming.local_port)
        .unwrap();
    println!(
        "[Chat] 双方下线：小明={:?}，小红={:?}",
        internet
            .tcp_state(xiaoming_node, xiaoming.local_port)
            .unwrap(),
        internet
            .tcp_state(xiaohong_node, xiaohong.local_port)
            .unwrap()
    );
    println!("结论：第一条消息经历丢包与重传，但 Chat Application 恰好收到一次。\n");
}

// 正式验收：一次 browser.open(URL) 驱动 DNS → TCP → HTTP → Close 全流程。
fn demo_v10_browser_open() {
    println!("========== v1.0 毕业验收：browser.open(URL) ==========");
    println!("拓扑：Browser -- R1 -- R2 -- R3 -- Web");
    println!("                       └── DNS\n");
    let (mut internet, browser_node, dns_node, web_node, r2, dns_ip, web_ip) =
        build_v10_browser_topology();

    internet
        .bind_dns_server(
            dns_node,
            DnsServer::new(
                "Authoritative DNS",
                dns_ip,
                vec![DnsRecord::a("www.tinynet.com", web_ip, 300)],
            ),
        )
        .unwrap();
    let mut web = HttpServer::new("www.tinynet.com");
    web.add_resource("/index.html", "<h1>Hello TinyNet!</h1>");
    internet.bind_http_server(web_node, 80, web).unwrap();
    let browser = internet.install_browser(browser_node, dns_ip).unwrap();

    // 故障注入属于 Link 配置，不属于 Browser。它会在 HTTP GET 发出前生效。
    internet
        .drop_browser_http_once_at(
            browser_node,
            Endpoint {
                node: r2,
                interface: 1,
            },
        )
        .unwrap();

    println!("Demo 的全部业务代码只有：");
    println!("  browser.open(\"http://www.tinynet.com/index.html\");");
    println!("  internet.run();\n");
    browser
        .open(&mut internet, "http://www.tinynet.com/index.html")
        .unwrap();
    internet.run().unwrap();

    for event in &internet.trace {
        match event {
            InternetTrace::ArpRequest {
                time_ms,
                node,
                target_ip,
                ..
            } => println!(
                "[t={time_ms:>3}ms] [ARP] {} resolves {}",
                internet.node_name(*node),
                target_ip.to_dotted()
            ),
            InternetTrace::BrowserResolved {
                time_ms,
                host_name,
                address,
                ..
            } => println!(
                "[t={time_ms:>3}ms] [DNS] {host_name} → {}",
                address.to_dotted()
            ),
            InternetTrace::TcpSent {
                time_ms,
                node,
                segment,
                retransmission,
                ..
            } if segment.syn || segment.fin || *retransmission => println!(
                "[t={time_ms:>3}ms] [TCP] {} [{}] seq={}{}",
                internet.node_name(*node),
                segment.flags(),
                segment.seq,
                if *retransmission { " RETRANSMIT" } else { "" }
            ),
            InternetTrace::LinkDropped { time_ms, from, .. } => println!(
                "[t={time_ms:>3}ms] [LINK] DROP {}:eth{} 的 HTTP 数据",
                internet.node_name(from.node),
                from.interface
            ),
            InternetTrace::TcpTimeout {
                time_ms, node, seq, ..
            } => println!(
                "[t={time_ms:>3}ms] [RTO] {} timeout seq={seq}",
                internet.node_name(*node)
            ),
            InternetTrace::HttpHandled {
                time_ms,
                node,
                path,
                status_code,
            } => println!(
                "[t={time_ms:>3}ms] [HTTP] {} GET {path} → {status_code}",
                internet.node_name(*node)
            ),
            InternetTrace::BrowserRendered {
                time_ms,
                status_code,
                ..
            } => println!("[t={time_ms:>3}ms] [Browser] render HTTP {status_code}"),
            _ => {}
        }
    }

    let response = browser.response(&internet).unwrap().unwrap();
    println!("\n┌──────────── Browser ────────────┐");
    println!("│ http://www.tinynet.com/index.html");
    println!("│ HTTP/1.1 {} {}", response.status_code, response.reason);
    println!("│ {}", response.body);
    println!("└────────────────────────────────┘");
    println!(
        "验收：Browser={:?}，Client TCP={:?}，Server TCP={:?}",
        browser.state(&internet).unwrap(),
        internet.tcp_state(browser_node, 50_000).unwrap(),
        internet.tcp_state(web_node, 80).unwrap()
    );
    println!("DNS、ARP、路由、TCP、HTTP、重传和关闭均由 EventQueue 自动推进。\n");
}

fn print_chat_reliability_trace(internet: &MiniInternet, start: usize) {
    for event in &internet.trace[start..] {
        match event {
            InternetTrace::LinkDropped { time_ms, from, .. } => println!(
                "  [t={time_ms}ms / Link] DROP {}:eth{} 上的聊天数据",
                internet.node_name(from.node),
                from.interface
            ),
            InternetTrace::TcpTimeout {
                time_ms, node, seq, ..
            } => println!(
                "  [t={time_ms}ms / TCP] {} RTO，seq={seq} 尚未确认",
                internet.node_name(*node)
            ),
            InternetTrace::TcpSent {
                time_ms,
                node,
                segment,
                retransmission: true,
                ..
            } => println!(
                "  [t={time_ms}ms / TCP] {} retransmit seq={} ({} bytes)",
                internet.node_name(*node),
                segment.seq,
                segment.payload.len()
            ),
            _ => {}
        }
    }
}

fn build_v10_browser_topology() -> (
    MiniInternet,
    crate::network::NodeId,
    crate::network::NodeId,
    crate::network::NodeId,
    crate::network::NodeId,
    Ipv4Addr,
    Ipv4Addr,
) {
    let lan = Ipv4Addr { value: 0xFFFF_FF00 };
    let p2p = Ipv4Addr { value: 0xFFFF_FFFC };
    let browser_ip = Ipv4Addr { value: 0xC0A8_0102 };
    let dns_ip = Ipv4Addr { value: 0x0A00_3535 }; // 10.0.53.53
    let web_ip = Ipv4Addr { value: 0x0A00_0302 };

    let mut browser_routes = RoutingTable::new();
    browser_routes.add_direct_route(0, browser_ip, lan);
    browser_routes.add_default_route(0, Ipv4Addr { value: 0xC0A8_0101 });
    let browser = Host::new(
        "Browser",
        browser_ip,
        lan,
        browser_routes,
        MacAddr::new([2, 0, 0, 0, 1, 2]),
    );

    let mut dns_routes = RoutingTable::new();
    dns_routes.add_direct_route(0, dns_ip, lan);
    dns_routes.add_default_route(0, Ipv4Addr { value: 0x0A00_3501 });
    let dns = Host::new(
        "DNS",
        dns_ip,
        lan,
        dns_routes,
        MacAddr::new([2, 0, 0, 0, 53, 53]),
    );

    let mut web_routes = RoutingTable::new();
    web_routes.add_direct_route(0, web_ip, lan);
    web_routes.add_default_route(0, Ipv4Addr { value: 0x0A00_0301 });
    let web = Host::new(
        "Web",
        web_ip,
        lan,
        web_routes,
        MacAddr::new([2, 0, 0, 0, 4, 2]),
    );

    let mut r1_routes = RoutingTable::new();
    r1_routes.add_direct_route(0, Ipv4Addr { value: 0xC0A8_0101 }, lan);
    r1_routes.add_direct_route(1, Ipv4Addr { value: 0x0A00_0C01 }, p2p);
    r1_routes.add_route(
        Ipv4Addr { value: 0x0A00_3500 },
        24,
        Ipv4Addr { value: 0x0A00_0C02 },
        1,
    );
    r1_routes.add_route(
        Ipv4Addr { value: 0x0A00_0300 },
        24,
        Ipv4Addr { value: 0x0A00_0C02 },
        1,
    );
    let r1 = Router::new(
        "R1",
        vec![
            Interface::new(
                "lan-browser",
                Ipv4Addr { value: 0xC0A8_0101 },
                lan,
                MacAddr::new([2, 0, 0, 0, 1, 1]),
            ),
            Interface::new(
                "to-r2",
                Ipv4Addr { value: 0x0A00_0C01 },
                p2p,
                MacAddr::new([2, 0, 0, 0, 12, 1]),
            ),
        ],
        r1_routes,
    );

    let mut r2_routes = RoutingTable::new();
    r2_routes.add_direct_route(0, Ipv4Addr { value: 0x0A00_0C02 }, p2p);
    r2_routes.add_direct_route(1, Ipv4Addr { value: 0x0A00_1701 }, p2p);
    r2_routes.add_direct_route(2, Ipv4Addr { value: 0x0A00_3501 }, lan);
    r2_routes.add_route(
        Ipv4Addr { value: 0xC0A8_0100 },
        24,
        Ipv4Addr { value: 0x0A00_0C01 },
        0,
    );
    r2_routes.add_route(
        Ipv4Addr { value: 0x0A00_0300 },
        24,
        Ipv4Addr { value: 0x0A00_1702 },
        1,
    );
    let r2 = Router::new(
        "R2",
        vec![
            Interface::new(
                "to-r1",
                Ipv4Addr { value: 0x0A00_0C02 },
                p2p,
                MacAddr::new([2, 0, 0, 0, 12, 2]),
            ),
            Interface::new(
                "to-r3",
                Ipv4Addr { value: 0x0A00_1701 },
                p2p,
                MacAddr::new([2, 0, 0, 0, 23, 1]),
            ),
            Interface::new(
                "lan-dns",
                Ipv4Addr { value: 0x0A00_3501 },
                lan,
                MacAddr::new([2, 0, 0, 0, 53, 1]),
            ),
        ],
        r2_routes,
    );

    let mut r3_routes = RoutingTable::new();
    r3_routes.add_direct_route(0, Ipv4Addr { value: 0x0A00_1702 }, p2p);
    r3_routes.add_direct_route(1, Ipv4Addr { value: 0x0A00_0301 }, lan);
    r3_routes.add_route(
        Ipv4Addr { value: 0xC0A8_0100 },
        24,
        Ipv4Addr { value: 0x0A00_1701 },
        0,
    );
    r3_routes.add_route(
        Ipv4Addr { value: 0x0A00_3500 },
        24,
        Ipv4Addr { value: 0x0A00_1701 },
        0,
    );
    let r3 = Router::new(
        "R3",
        vec![
            Interface::new(
                "to-r2",
                Ipv4Addr { value: 0x0A00_1702 },
                p2p,
                MacAddr::new([2, 0, 0, 0, 23, 2]),
            ),
            Interface::new(
                "lan-web",
                Ipv4Addr { value: 0x0A00_0301 },
                lan,
                MacAddr::new([2, 0, 0, 0, 4, 1]),
            ),
        ],
        r3_routes,
    );

    let mut internet = MiniInternet::new();
    let browser_id = internet.add_host(browser);
    let r1_id = internet.add_router(r1);
    let r2_id = internet.add_router(r2);
    let r3_id = internet.add_router(r3);
    let dns_id = internet.add_host(dns);
    let web_id = internet.add_host(web);
    for (a, b) in [
        (
            Endpoint {
                node: browser_id,
                interface: 0,
            },
            Endpoint {
                node: r1_id,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r1_id,
                interface: 1,
            },
            Endpoint {
                node: r2_id,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r2_id,
                interface: 1,
            },
            Endpoint {
                node: r3_id,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r2_id,
                interface: 2,
            },
            Endpoint {
                node: dns_id,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r3_id,
                interface: 1,
            },
            Endpoint {
                node: web_id,
                interface: 0,
            },
        ),
    ] {
        internet.connect(a, b, 5, 0).unwrap();
    }
    (internet, browser_id, dns_id, web_id, r2_id, dns_ip, web_ip)
}

fn build_v10_three_router_topology(
    left_name: &str,
    right_name: &str,
) -> (
    MiniInternet,
    crate::network::NodeId,
    crate::network::NodeId,
    crate::network::NodeId,
    crate::network::NodeId,
    Ipv4Addr,
) {
    let lan_mask = Ipv4Addr { value: 0xFFFF_FF00 };
    let link_mask = Ipv4Addr { value: 0xFFFF_FFFC };
    let browser_ip = Ipv4Addr { value: 0xC0A8_0102 };
    let web_ip = Ipv4Addr { value: 0x0A00_0302 };

    let mut browser_routes = RoutingTable::new();
    browser_routes.add_direct_route(0, browser_ip, lan_mask);
    browser_routes.add_default_route(0, Ipv4Addr { value: 0xC0A8_0101 });
    let browser = Host::new(
        left_name,
        browser_ip,
        lan_mask,
        browser_routes,
        MacAddr::new([2, 0, 0, 0, 1, 2]),
    );
    let mut web_routes = RoutingTable::new();
    web_routes.add_direct_route(0, web_ip, lan_mask);
    web_routes.add_default_route(0, Ipv4Addr { value: 0x0A00_0301 });
    let web = Host::new(
        right_name,
        web_ip,
        lan_mask,
        web_routes,
        MacAddr::new([2, 0, 0, 0, 4, 2]),
    );

    let mut r1_routes = RoutingTable::new();
    r1_routes.add_direct_route(0, Ipv4Addr { value: 0xC0A8_0101 }, lan_mask);
    r1_routes.add_direct_route(1, Ipv4Addr { value: 0x0A00_0C01 }, link_mask);
    r1_routes.add_route(
        Ipv4Addr { value: 0x0A00_0300 },
        24,
        Ipv4Addr { value: 0x0A00_0C02 },
        1,
    );
    let r1_node = Router::new(
        "R1",
        vec![
            Interface::new(
                "lan-browser",
                Ipv4Addr { value: 0xC0A8_0101 },
                lan_mask,
                MacAddr::new([2, 0, 0, 0, 1, 1]),
            ),
            Interface::new(
                "to-r2",
                Ipv4Addr { value: 0x0A00_0C01 },
                link_mask,
                MacAddr::new([2, 0, 0, 0, 12, 1]),
            ),
        ],
        r1_routes,
    );

    let mut r2_routes = RoutingTable::new();
    r2_routes.add_direct_route(0, Ipv4Addr { value: 0x0A00_0C02 }, link_mask);
    r2_routes.add_direct_route(1, Ipv4Addr { value: 0x0A00_1701 }, link_mask);
    r2_routes.add_route(
        Ipv4Addr { value: 0xC0A8_0100 },
        24,
        Ipv4Addr { value: 0x0A00_0C01 },
        0,
    );
    r2_routes.add_route(
        Ipv4Addr { value: 0x0A00_0300 },
        24,
        Ipv4Addr { value: 0x0A00_1702 },
        1,
    );
    let r2_node = Router::new(
        "R2",
        vec![
            Interface::new(
                "to-r1",
                Ipv4Addr { value: 0x0A00_0C02 },
                link_mask,
                MacAddr::new([2, 0, 0, 0, 12, 2]),
            ),
            Interface::new(
                "to-r3",
                Ipv4Addr { value: 0x0A00_1701 },
                link_mask,
                MacAddr::new([2, 0, 0, 0, 23, 1]),
            ),
        ],
        r2_routes,
    );

    let mut r3_routes = RoutingTable::new();
    r3_routes.add_direct_route(0, Ipv4Addr { value: 0x0A00_1702 }, link_mask);
    r3_routes.add_direct_route(1, Ipv4Addr { value: 0x0A00_0301 }, lan_mask);
    r3_routes.add_route(
        Ipv4Addr { value: 0xC0A8_0100 },
        24,
        Ipv4Addr { value: 0x0A00_1701 },
        0,
    );
    let r3_node = Router::new(
        "R3",
        vec![
            Interface::new(
                "to-r2",
                Ipv4Addr { value: 0x0A00_1702 },
                link_mask,
                MacAddr::new([2, 0, 0, 0, 23, 2]),
            ),
            Interface::new(
                "lan-web",
                Ipv4Addr { value: 0x0A00_0301 },
                lan_mask,
                MacAddr::new([2, 0, 0, 0, 4, 1]),
            ),
        ],
        r3_routes,
    );

    let mut internet = MiniInternet::new();
    let browser_id = internet.add_host(browser);
    let r1_id = internet.add_router(r1_node);
    let r2_id = internet.add_router(r2_node);
    let r3_id = internet.add_router(r3_node);
    let web_id = internet.add_host(web);
    for (a, b) in [
        (
            Endpoint {
                node: browser_id,
                interface: 0,
            },
            Endpoint {
                node: r1_id,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r1_id,
                interface: 1,
            },
            Endpoint {
                node: r2_id,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r2_id,
                interface: 1,
            },
            Endpoint {
                node: r3_id,
                interface: 0,
            },
        ),
        (
            Endpoint {
                node: r3_id,
                interface: 1,
            },
            Endpoint {
                node: web_id,
                interface: 0,
            },
        ),
    ] {
        internet.connect(a, b, 5, 0).unwrap();
    }
    (internet, browser_id, web_id, r1_id, r2_id, web_ip)
}

// =============================================================================
// 扩展实验（不占用版本号）
// OSPF/BGP 是在主线完成后的路由算法补充，不改变 v0.1～v1.0 的分层。
// =============================================================================
pub fn demo_routing_extensions() {
    demo_ospf_extension();
    demo_bgp_extension();
}

// 扩展实验 A：简化 OSPF（链路状态 + SPF 最短路径）。
fn demo_ospf_extension() {
    println!("========== 扩展实验：简化 OSPF ==========");
    //       R1
    //      /  \
    //     R2--R3
    //      \  /
    //       R4
    let mut topology = Topology::new(vec![
        Link {
            from: "R1",
            to: "R2",
            cost: 2,
        },
        Link {
            from: "R1",
            to: "R3",
            cost: 6,
        },
        Link {
            from: "R2",
            to: "R3",
            cost: 2,
        },
        Link {
            from: "R2",
            to: "R4",
            cost: 2,
        },
        Link {
            from: "R3",
            to: "R4",
            cost: 1,
        },
    ]);
    println!("--- 初始：R1 运行 SPF ---");
    topology.print_spf("R1");
    println!("\n--- R2-R4 链路断开后重新计算 ---");
    topology.bring_link_down("R2", "R4");
    topology.print_spf("R1");
    println!("R4 的开销从 4 变为 5，R1 自动绕行 R2-R3-R4。\n");
}

// 扩展实验 B：简化 BGP（路径向量 + 策略选路）。
fn demo_bgp_extension() {
    println!("========== 扩展实验：简化版 BGP(路径向量 + 策略选路) ==========");
    println!();

    // 目的前缀:20.0.0.0/8,由 AS3 始发
    let prefix = Prefix::new(Ipv4Addr { value: 20 << 24 }, 8);

    println!("背景:AS1 要去 20.0.0.0/8(由 AS3 始发)。两个邻居都来广播这条前缀:");
    println!("       AS2 说:走我 → 路径 [AS2, AS3]");
    println!("       AS4 说:走我 → 路径 [AS4, AS3]");
    println!("       AS_PATH 一样长,该听谁的?这就是策略(local_pref)的用武之地。");
    println!();

    println!("--- 场景一:没有策略,两条 AS_PATH 一样长 → 兜底比较 ---");
    let r1 = BgpRoute::new(prefix, vec![2, 3]);
    let r2 = BgpRoute::new(prefix, vec![4, 3]);
    println!("  候选 1: {}", r1.to_string());
    println!("  候选 2: {}", r2.to_string());
    println!("  local_pref 平局 → AS_PATH 一样长 → 按 AS_PATH 字典序兜底");
    let routes = [r1, r2];
    let best = select_bgp_route(&routes);
    println!("→ 选中: {}", best.to_string());
    println!();

    println!("--- 场景二:AS1 配置策略「偏好 AS4」→ 策略优先于一切 ---");
    let mut r1 = BgpRoute::new(prefix, vec![2, 3]);
    let mut r2 = BgpRoute::new(prefix, vec![4, 3]);

    let mut as1_policy = BgpPolicy::new(1);
    as1_policy.prefer(4, 200); // 来自 AS4 的路由,local_pref 提到 200
    as1_policy.apply(&mut r1);
    as1_policy.apply(&mut r2);

    println!(
        "  AS{} 的策略:偏好 AS4 → 来自它的路由 local_pref = 200",
        as1_policy.asn
    );
    println!("  应用策略后:");
    println!("  候选 1: {}", r1.to_string());
    println!("  候选 2: {}", r2.to_string());
    println!("  AS_PATH 还是一样长,但 local_pref 200 > 100");
    let routes = [r1, r2];
    let best = select_bgp_route(&routes);
    println!("→ 选中: {}  ← 策略胜出", best.to_string());
    println!();

    println!("--- 场景三:local_pref 相同,AS_PATH 越短越优先 ---");
    let r1 = BgpRoute::new(prefix, vec![2, 3]); // 2 跳
    let r2 = BgpRoute::new(prefix, vec![4, 5, 3]); // 3 跳
    println!("  候选 1: {}   ({} 跳)", r1.to_string(), r1.as_path.len());
    println!("  候选 2: {}   ({} 跳)", r2.to_string(), r2.as_path.len());
    let routes = [r1, r2];
    let best = select_bgp_route(&routes);
    println!("→ 选中: {}  ← 短路径胜出", best.to_string());
    println!();

    println!("--- 场景四:同一张物理图,OSPF(Dijkstra)和 BGP 的答案不一样 ---");
    println!("  物理拓扑(数字 = 链路开销):");
    println!("    AS1 --1-- AS2 --1-- AS3   ← 到 AS3 物理上近(总开销 2)");
    println!("      \\             /");
    println!("       \\--10--AS4--/          ← 到 AS3 物理上远(总开销 20)");
    println!();
    let topo = Topology::new(vec![
        Link {
            from: "AS1",
            to: "AS2",
            cost: 1,
        },
        Link {
            from: "AS2",
            to: "AS3",
            cost: 1,
        },
        Link {
            from: "AS1",
            to: "AS4",
            cost: 10,
        },
        Link {
            from: "AS4",
            to: "AS3",
            cost: 10,
        },
    ]);
    println!("  [OSPF/SPF 视角] 按链路开销算到 AS3(20.0.0.0/8 的始发 AS)的最短路径:");
    topo.print_spf("AS1");
    println!("  → Dijkstra 选:走 AS2(开销 2)");
    println!();

    println!("  [BGP 视角] 同样的目的地,但 AS1 的策略是「偏好 AS4」:");
    let mut r1 = BgpRoute::new(prefix, vec![2, 3]);
    let mut r2 = BgpRoute::new(prefix, vec![4, 3]);
    let mut as1_policy = BgpPolicy::new(1);
    as1_policy.prefer(4, 200);
    as1_policy.apply(&mut r1);
    as1_policy.apply(&mut r2);
    println!("  候选 1: {}", r1.to_string());
    println!("  候选 2: {}", r2.to_string());
    let routes = [r1, r2];
    let best = select_bgp_route(&routes);
    println!("→ BGP 选:{}  ← 即使物理上绕远,策略说了算", best.to_string());
    println!();

    println!("结论:OSPF(IGP)在 AS 内部用 Dijkstra 比链路开销;");
    println!("     BGP(EGP)在 AS 之间用策略 + AS_PATH 比路径。");
    println!("     跨 AS 你管不着别人的内部开销,只能靠策略约定「我信谁、我偏爱谁」。");
    println!("     所以:路由选择不再只是 Dijkstra。");
}
