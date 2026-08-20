use std::rc::Rc;

use crate::address::{Ipv4Addr, MacAddr};
use crate::bgp::{select_bgp_route, BgpPolicy, BgpRoute, Prefix};
use crate::host::Host;
use crate::ospf::{Link, Topology};
use crate::packet::IpPacket;
use crate::routing::{ForwardOutcome, Interface, Router, RoutingTable};
use crate::switch::Switch;
use crate::reliable::{GbnReceiver, GbnSender, LossyNetwork, SrReceiver, SrSender};
use crate::tcp::{TcpConnection, TcpSegment};

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

// ========== v0.4：可靠传输（GBN 与 SR 对照实验） ==========
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
                    println!("recv {} -> drop（期望 seq={}）", received_seq, gbn_receiver.expected_seq);
                } else {
                    println!("recv {} -> deliver, ACK {}", received_seq, result.ack.unwrap());
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
    println!("GBN 完成：send_base={}，未确认队列={}", gbn_sender.send_base, gbn_sender.unacked_queue.len());
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
                    println!("recv {} -> buffer, ACK {}", received_seq, result.ack.unwrap());
                } else {
                    println!("recv {} -> deliver, ACK {}", received_seq, result.ack.unwrap());
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
    println!("deliver: {}", delivered.iter().map(u32::to_string).collect::<Vec<_>>().join(" "));
    println!("SR 完成：send_base={}，buffer={}，未确认队列={}",
        sr_sender.send_base, sr_receiver.buffer.len(), sr_sender.unacked_queue.len());
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
    segments.iter().map(|segment| segment.seq.to_string()).collect::<Vec<_>>().join(" ")
}

// ========== v0.5：TCP（三次握手 + 滑动窗口 + 流量控制 + 四次挥手） ==========
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
    println!("结论：TCP 用握手建立双方序号空间，用滑动窗口连续发送，用 rwnd 防止淹没接收方，最后用四次挥手独立关闭两个方向。\n");
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

// ========== v0.7:简化版 BGP(路径向量 + 策略选路) ==========
pub fn demo_v07() {
    println!("========== v0.7:简化版 BGP(路径向量 + 策略选路) ==========");
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

    println!("  AS{} 的策略:偏好 AS4 → 来自它的路由 local_pref = 200", as1_policy.asn);
    println!("  应用策略后:");
    println!("  候选 1: {}", r1.to_string());
    println!("  候选 2: {}", r2.to_string());
    println!("  AS_PATH 还是一样长,但 local_pref 200 > 100");
    let routes = [r1, r2];
    let best = select_bgp_route(&routes);
    println!("→ 选中: {}  ← 策略胜出", best.to_string());
    println!();

    println!("--- 场景三:local_pref 相同,AS_PATH 越短越优先 ---");
    let r1 = BgpRoute::new(prefix, vec![2, 3]);     // 2 跳
    let r2 = BgpRoute::new(prefix, vec![4, 5, 3]);  // 3 跳
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
        Link { from: "AS1", to: "AS2", cost: 1 },
        Link { from: "AS2", to: "AS3", cost: 1 },
        Link { from: "AS1", to: "AS4", cost: 10 },
        Link { from: "AS4", to: "AS3", cost: 10 },
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
