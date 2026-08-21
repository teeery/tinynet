use std::collections::HashMap;

use crate::address::{Ipv4Addr, MacAddr};
use crate::dns::{DNS_PORT, DnsMessage, DnsRecordData, DnsRecordType, DnsResolveError, DnsServer};
use crate::host::Host;
use crate::http::{HttpRequest, HttpResponse, HttpServer};
use crate::network::{
    Endpoint, Network, NetworkError, NetworkEvent, NodeId, NodeKind, SendDisposition,
};
use crate::packet::{ArpPacket, EthernetFrame, EthernetPayload, IpPacket, IpPayload};
use crate::routing::{Router, RouterAction, RouterDropReason};
use crate::tcp::{TcpConnection, TcpSegment, TcpState};
use crate::udp::{UdpDatagram, UdpPayload};

// ========== v1.0：统一协议栈运行时 ==========
// Network 只投递 Ethernet Frame；这里组合 ARP、IP、UDP 与节点行为。
// pending_arp 保存已完成路由选择、但仍在等待下一跳 MAC 的 IP 包。
// 两个变体都只存在于教学规模的节点表中；保持字段展开可让各层状态一眼可见。
#[allow(clippy::large_enum_variant)]
enum StackNode {
    Host {
        host: Host,
        arp_table: HashMap<Ipv4Addr, MacAddr>,
        pending_arp: HashMap<Ipv4Addr, Vec<IpPacket>>,
        inbox: Vec<IpPacket>,
        udp_sockets: HashMap<u16, Vec<(Ipv4Addr, UdpDatagram)>>,
        dns_server: Option<DnsServer>,
        tcp_sockets: HashMap<u16, TcpSocket>,
        http_servers: HashMap<u16, HttpServer>,
        browser: Option<BrowserRuntime>,
    },
    Router {
        router: Router,
        arp_table: HashMap<(usize, Ipv4Addr), MacAddr>,
        pending_arp: HashMap<(usize, Ipv4Addr), Vec<IpPacket>>,
    },
}

// 当前教学运行时每个本地端口维护一条连接；五元组扩展留到后续实验。
struct TcpSocket {
    remote_ip: Option<Ipv4Addr>,
    connection: TcpConnection,
}

#[derive(Clone)]
struct TcpTimer {
    node: NodeId,
    local_port: u16,
    destination: Ipv4Addr,
    segment: TcpSegment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserState {
    Idle,
    Resolving,
    Connecting,
    Requesting,
    Closing,
    Complete,
}

struct BrowserRuntime {
    dns_server: Ipv4Addr,
    dns_port: u16,
    tcp_port: u16,
    state: BrowserState,
    host_name: String,
    path: String,
    response: Option<HttpResponse>,
    drop_http_at: Option<Endpoint>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Browser {
    node: NodeId,
}

impl Browser {
    pub fn open(self, internet: &mut MiniInternet, url: &str) -> Result<(), InternetError> {
        internet.browser_open(self.node, url)
    }

    pub fn state(self, internet: &MiniInternet) -> Result<BrowserState, InternetError> {
        internet.browser_state(self.node)
    }

    pub fn response(self, internet: &MiniInternet) -> Result<Option<&HttpResponse>, InternetError> {
        internet.browser_response(self.node)
    }
}

enum ApplicationAction {
    TcpConnect {
        local_port: u16,
        destination: Ipv4Addr,
        remote_port: u16,
    },
    HttpGet {
        local_port: u16,
        host_name: String,
        path: String,
    },
    TcpClose {
        local_port: u16,
    },
    ExpireTimeWait {
        local_port: u16,
    },
    DropNextFrame {
        from: Endpoint,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InternetTrace {
    HostSent {
        time_ms: u64,
        node: NodeId,
        destination: Ipv4Addr,
        next_hop: Ipv4Addr,
    },
    ArpRequest {
        time_ms: u64,
        node: NodeId,
        interface: usize,
        target_ip: Ipv4Addr,
    },
    ArpReply {
        time_ms: u64,
        node: NodeId,
        interface: usize,
        target_ip: Ipv4Addr,
    },
    ArpLearned {
        time_ms: u64,
        node: NodeId,
        interface: usize,
        ip: Ipv4Addr,
        mac: MacAddr,
    },
    FrameArrived {
        time_ms: u64,
        from: Endpoint,
        to: Endpoint,
        src_mac: MacAddr,
        dst_mac: MacAddr,
    },
    RouterForwarded {
        time_ms: u64,
        node: NodeId,
        incoming_iface: usize,
        outgoing_iface: usize,
        next_hop: Ipv4Addr,
        ttl: u8,
    },
    RouterReplied {
        time_ms: u64,
        node: NodeId,
        outgoing_iface: usize,
        next_hop: Ipv4Addr,
    },
    HostReceived {
        time_ms: u64,
        node: NodeId,
        packet: IpPacket,
    },
    UdpDelivered {
        time_ms: u64,
        node: NodeId,
        src_port: u16,
        dst_port: u16,
    },
    DnsAnswered {
        time_ms: u64,
        node: NodeId,
        client: Ipv4Addr,
        query_id: u16,
    },
    TcpSent {
        time_ms: u64,
        node: NodeId,
        destination: Ipv4Addr,
        segment: TcpSegment,
        retransmission: bool,
    },
    TcpReceived {
        time_ms: u64,
        node: NodeId,
        source: Ipv4Addr,
        segment: TcpSegment,
    },
    TcpStateChanged {
        time_ms: u64,
        node: NodeId,
        local_port: u16,
        old: TcpState,
        new: TcpState,
    },
    TcpTimeout {
        time_ms: u64,
        node: NodeId,
        local_port: u16,
        seq: u32,
    },
    HttpHandled {
        time_ms: u64,
        node: NodeId,
        path: String,
        status_code: u16,
    },
    BrowserResolved {
        time_ms: u64,
        node: NodeId,
        host_name: String,
        address: Ipv4Addr,
    },
    BrowserRendered {
        time_ms: u64,
        node: NodeId,
        status_code: u16,
    },
    LinkDropped {
        time_ms: u64,
        from: Endpoint,
        destination: Endpoint,
    },
    RouterDropped {
        time_ms: u64,
        node: NodeId,
        reason: RouterDropReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InternetError {
    Network(NetworkError),
    Dns(DnsResolveError),
    UnknownRuntimeNode(NodeId),
    NotAHost(NodeId),
    InvalidInterface(Endpoint),
    NoRoute { node: NodeId, destination: Ipv4Addr },
    DnsAddressMismatch { host: Ipv4Addr, server: Ipv4Addr },
    Tcp(String),
    Http(String),
    PortInUse { node: NodeId, port: u16 },
    NoTcpSocket { node: NodeId, port: u16 },
    TcpPeerUnknown { node: NodeId, port: u16 },
    BrowserMissing(NodeId),
    BrowserBusy(NodeId),
    InvalidUrl(String),
}

impl From<NetworkError> for InternetError {
    fn from(error: NetworkError) -> Self {
        Self::Network(error)
    }
}

impl From<DnsResolveError> for InternetError {
    fn from(error: DnsResolveError) -> Self {
        Self::Dns(error)
    }
}

struct OutgoingFrame {
    from: Endpoint,
    frame: EthernetFrame,
}

struct NodeProcessing {
    frames: Vec<OutgoingFrame>,
    traces: Vec<InternetTrace>,
    // DNS Server 产生的响应仍要从 Host 的正常 IP/ARP 发送路径出去。
    generated_packets: Vec<IpPacket>,
    application_actions: Vec<ApplicationAction>,
}

impl NodeProcessing {
    fn new() -> Self {
        Self {
            frames: Vec::new(),
            traces: Vec::new(),
            generated_packets: Vec::new(),
            application_actions: Vec::new(),
        }
    }
}

pub struct MiniInternet {
    pub network: Network,
    pub trace: Vec<InternetTrace>,
    nodes: HashMap<NodeId, StackNode>,
    tcp_timers: HashMap<u64, TcpTimer>,
    next_timer_id: u64,
    tcp_rto_ms: u64,
}

impl MiniInternet {
    pub fn new() -> Self {
        Self {
            network: Network::new(),
            trace: Vec::new(),
            nodes: HashMap::new(),
            tcp_timers: HashMap::new(),
            next_timer_id: 1,
            tcp_rto_ms: 100,
        }
    }

    pub fn add_host(&mut self, host: Host) -> NodeId {
        let id = self.network.add_node(host.name(), NodeKind::Host, 1);
        self.nodes.insert(
            id,
            StackNode::Host {
                host,
                arp_table: HashMap::new(),
                pending_arp: HashMap::new(),
                inbox: Vec::new(),
                udp_sockets: HashMap::new(),
                dns_server: None,
                tcp_sockets: HashMap::new(),
                http_servers: HashMap::new(),
                browser: None,
            },
        );
        id
    }

    pub fn add_router(&mut self, router: Router) -> NodeId {
        let id = self
            .network
            .add_node(&router.name, NodeKind::Router, router.interfaces.len());
        self.nodes.insert(
            id,
            StackNode::Router {
                router,
                arp_table: HashMap::new(),
                pending_arp: HashMap::new(),
            },
        );
        id
    }

    pub fn connect(
        &mut self,
        a: Endpoint,
        b: Endpoint,
        delay_ms: u64,
        loss_percent: u8,
    ) -> Result<(), InternetError> {
        self.network
            .connect(a, b, delay_ms, loss_percent)
            .map_err(Into::into)
    }

    pub fn install_browser(
        &mut self,
        host_id: NodeId,
        dns_server: Ipv4Addr,
    ) -> Result<Browser, InternetError> {
        match self
            .nodes
            .get_mut(&host_id)
            .ok_or(InternetError::UnknownRuntimeNode(host_id))?
        {
            StackNode::Host { browser, .. } => {
                *browser = Some(BrowserRuntime {
                    dns_server,
                    dns_port: 53_000,
                    tcp_port: 50_000,
                    state: BrowserState::Idle,
                    host_name: String::new(),
                    path: String::new(),
                    response: None,
                    drop_http_at: None,
                });
                Ok(Browser { node: host_id })
            }
            StackNode::Router { .. } => Err(InternetError::NotAHost(host_id)),
        }
    }

    // 故障属于实验拓扑配置；Browser 自己仍然只执行 open(URL)。
    pub fn drop_browser_http_once_at(
        &mut self,
        host_id: NodeId,
        from: Endpoint,
    ) -> Result<(), InternetError> {
        let browser = self.browser_mut(host_id)?;
        browser.drop_http_at = Some(from);
        Ok(())
    }

    fn browser_open(&mut self, host_id: NodeId, url: &str) -> Result<(), InternetError> {
        let (host_name, path) = parse_http_url(url)?;
        let (dns_server, dns_port) = {
            let browser = self.browser_mut(host_id)?;
            if browser.state != BrowserState::Idle {
                return Err(InternetError::BrowserBusy(host_id));
            }
            browser.state = BrowserState::Resolving;
            browser.host_name = host_name.clone();
            browser.path = path;
            browser.response = None;
            (browser.dns_server, browser.dns_port)
        };
        self.send_udp(
            host_id,
            dns_server,
            UdpDatagram {
                src_port: dns_port,
                dst_port: DNS_PORT,
                payload: UdpPayload::Dns(DnsMessage::query(1_000, &host_name, DnsRecordType::A)),
            },
        )
    }

    fn browser_state(&self, host_id: NodeId) -> Result<BrowserState, InternetError> {
        Ok(self.browser_ref(host_id)?.state)
    }

    fn browser_response(&self, host_id: NodeId) -> Result<Option<&HttpResponse>, InternetError> {
        Ok(self.browser_ref(host_id)?.response.as_ref())
    }

    fn browser_ref(&self, host_id: NodeId) -> Result<&BrowserRuntime, InternetError> {
        match self
            .nodes
            .get(&host_id)
            .ok_or(InternetError::UnknownRuntimeNode(host_id))?
        {
            StackNode::Host {
                browser: Some(browser),
                ..
            } => Ok(browser),
            StackNode::Host { browser: None, .. } => Err(InternetError::BrowserMissing(host_id)),
            StackNode::Router { .. } => Err(InternetError::NotAHost(host_id)),
        }
    }

    fn browser_mut(&mut self, host_id: NodeId) -> Result<&mut BrowserRuntime, InternetError> {
        match self
            .nodes
            .get_mut(&host_id)
            .ok_or(InternetError::UnknownRuntimeNode(host_id))?
        {
            StackNode::Host {
                browser: Some(browser),
                ..
            } => Ok(browser),
            StackNode::Host { browser: None, .. } => Err(InternetError::BrowserMissing(host_id)),
            StackNode::Router { .. } => Err(InternetError::NotAHost(host_id)),
        }
    }

    // DNS 是 Host 上绑定到 UDP/53 的服务，不再由 Demo 直接调用 handle_udp。
    pub fn bind_dns_server(
        &mut self,
        host_id: NodeId,
        server: DnsServer,
    ) -> Result<(), InternetError> {
        match self
            .nodes
            .get_mut(&host_id)
            .ok_or(InternetError::UnknownRuntimeNode(host_id))?
        {
            StackNode::Host {
                host, dns_server, ..
            } => {
                if host.ip() != server.ip {
                    return Err(InternetError::DnsAddressMismatch {
                        host: host.ip(),
                        server: server.ip,
                    });
                }
                *dns_server = Some(server);
                Ok(())
            }
            StackNode::Router { .. } => Err(InternetError::NotAHost(host_id)),
        }
    }

    pub fn bind_http_server(
        &mut self,
        host_id: NodeId,
        port: u16,
        server: HttpServer,
    ) -> Result<(), InternetError> {
        match self
            .nodes
            .get_mut(&host_id)
            .ok_or(InternetError::UnknownRuntimeNode(host_id))?
        {
            StackNode::Host {
                tcp_sockets,
                http_servers,
                ..
            } => {
                if tcp_sockets.contains_key(&port) {
                    return Err(InternetError::PortInUse {
                        node: host_id,
                        port,
                    });
                }
                tcp_sockets.insert(
                    port,
                    TcpSocket {
                        remote_ip: None,
                        connection: TcpConnection::listener(
                            "HTTP Server",
                            port,
                            20_000,
                            8192,
                            8192,
                        ),
                    },
                );
                http_servers.insert(port, server);
                Ok(())
            }
            StackNode::Router { .. } => Err(InternetError::NotAHost(host_id)),
        }
    }

    // 通用 TCP Application 可以绑定监听端口；Chat 不需要借用 HTTP 的语义。
    pub fn bind_tcp_listener(&mut self, host_id: NodeId, port: u16) -> Result<(), InternetError> {
        match self
            .nodes
            .get_mut(&host_id)
            .ok_or(InternetError::UnknownRuntimeNode(host_id))?
        {
            StackNode::Host { tcp_sockets, .. } => {
                if tcp_sockets.contains_key(&port) {
                    return Err(InternetError::PortInUse {
                        node: host_id,
                        port,
                    });
                }
                tcp_sockets.insert(
                    port,
                    TcpSocket {
                        remote_ip: None,
                        connection: TcpConnection::listener(
                            "Chat Listener",
                            port,
                            30_000,
                            8192,
                            8192,
                        ),
                    },
                );
                Ok(())
            }
            StackNode::Router { .. } => Err(InternetError::NotAHost(host_id)),
        }
    }

    pub fn tcp_connect(
        &mut self,
        host_id: NodeId,
        local_port: u16,
        destination: Ipv4Addr,
        remote_port: u16,
    ) -> Result<(), InternetError> {
        let syn = {
            let node = self
                .nodes
                .get_mut(&host_id)
                .ok_or(InternetError::UnknownRuntimeNode(host_id))?;
            let StackNode::Host { tcp_sockets, .. } = node else {
                return Err(InternetError::NotAHost(host_id));
            };
            if tcp_sockets.contains_key(&local_port) {
                return Err(InternetError::PortInUse {
                    node: host_id,
                    port: local_port,
                });
            }
            let mut connection =
                TcpConnection::client("HTTP Client", local_port, remote_port, 10_000, 8192, 8192);
            let syn = connection.connect().map_err(InternetError::Tcp)?;
            tcp_sockets.insert(
                local_port,
                TcpSocket {
                    remote_ip: Some(destination),
                    connection,
                },
            );
            syn
        };
        self.send_tcp_segment(host_id, destination, syn, false)
    }

    pub fn http_get(
        &mut self,
        host_id: NodeId,
        local_port: u16,
        host_name: &str,
        path: &str,
    ) -> Result<(), InternetError> {
        let (destination, segments) = {
            let node = self
                .nodes
                .get_mut(&host_id)
                .ok_or(InternetError::UnknownRuntimeNode(host_id))?;
            let StackNode::Host { tcp_sockets, .. } = node else {
                return Err(InternetError::NotAHost(host_id));
            };
            let socket = tcp_sockets
                .get_mut(&local_port)
                .ok_or(InternetError::NoTcpSocket {
                    node: host_id,
                    port: local_port,
                })?;
            let destination = socket.remote_ip.ok_or(InternetError::TcpPeerUnknown {
                node: host_id,
                port: local_port,
            })?;
            let request = HttpRequest::get(host_name, path);
            let segments = socket
                .connection
                .send_data(&request.to_bytes(), 1460)
                .map_err(InternetError::Tcp)?;
            (destination, segments)
        };
        for segment in segments {
            self.send_tcp_segment(host_id, destination, segment, false)?;
        }
        Ok(())
    }

    pub fn send_tcp_bytes(
        &mut self,
        host_id: NodeId,
        local_port: u16,
        bytes: &[u8],
    ) -> Result<(), InternetError> {
        let (destination, segments) = {
            let node = self
                .nodes
                .get_mut(&host_id)
                .ok_or(InternetError::UnknownRuntimeNode(host_id))?;
            let StackNode::Host { tcp_sockets, .. } = node else {
                return Err(InternetError::NotAHost(host_id));
            };
            let socket = tcp_sockets
                .get_mut(&local_port)
                .ok_or(InternetError::NoTcpSocket {
                    node: host_id,
                    port: local_port,
                })?;
            let destination = socket.remote_ip.ok_or(InternetError::TcpPeerUnknown {
                node: host_id,
                port: local_port,
            })?;
            let segments = socket
                .connection
                .send_data(bytes, 1460)
                .map_err(InternetError::Tcp)?;
            (destination, segments)
        };
        for segment in segments {
            self.send_tcp_segment(host_id, destination, segment, false)?;
        }
        Ok(())
    }

    pub fn read_tcp_bytes(
        &mut self,
        host_id: NodeId,
        local_port: u16,
    ) -> Result<Vec<u8>, InternetError> {
        let node = self
            .nodes
            .get_mut(&host_id)
            .ok_or(InternetError::UnknownRuntimeNode(host_id))?;
        let StackNode::Host { tcp_sockets, .. } = node else {
            return Err(InternetError::NotAHost(host_id));
        };
        let socket = tcp_sockets
            .get_mut(&local_port)
            .ok_or(InternetError::NoTcpSocket {
                node: host_id,
                port: local_port,
            })?;
        Ok(socket.connection.application_read(usize::MAX))
    }

    pub fn read_http_response(
        &mut self,
        host_id: NodeId,
        local_port: u16,
    ) -> Result<HttpResponse, InternetError> {
        let node = self
            .nodes
            .get_mut(&host_id)
            .ok_or(InternetError::UnknownRuntimeNode(host_id))?;
        let StackNode::Host { tcp_sockets, .. } = node else {
            return Err(InternetError::NotAHost(host_id));
        };
        let socket = tcp_sockets
            .get_mut(&local_port)
            .ok_or(InternetError::NoTcpSocket {
                node: host_id,
                port: local_port,
            })?;
        HttpResponse::parse(&socket.connection.application_read(usize::MAX))
            .map_err(InternetError::Http)
    }

    pub fn tcp_close(&mut self, host_id: NodeId, local_port: u16) -> Result<(), InternetError> {
        let (destination, fin) = {
            let node = self
                .nodes
                .get_mut(&host_id)
                .ok_or(InternetError::UnknownRuntimeNode(host_id))?;
            let StackNode::Host { tcp_sockets, .. } = node else {
                return Err(InternetError::NotAHost(host_id));
            };
            let socket = tcp_sockets
                .get_mut(&local_port)
                .ok_or(InternetError::NoTcpSocket {
                    node: host_id,
                    port: local_port,
                })?;
            let destination = socket.remote_ip.ok_or(InternetError::TcpPeerUnknown {
                node: host_id,
                port: local_port,
            })?;
            let fin = socket.connection.close().map_err(InternetError::Tcp)?;
            (destination, fin)
        };
        self.send_tcp_segment(host_id, destination, fin, false)
    }

    pub fn tcp_state(&self, host_id: NodeId, local_port: u16) -> Result<TcpState, InternetError> {
        match self
            .nodes
            .get(&host_id)
            .ok_or(InternetError::UnknownRuntimeNode(host_id))?
        {
            StackNode::Host { tcp_sockets, .. } => tcp_sockets
                .get(&local_port)
                .map(|socket| socket.connection.state)
                .ok_or(InternetError::NoTcpSocket {
                    node: host_id,
                    port: local_port,
                }),
            StackNode::Router { .. } => Err(InternetError::NotAHost(host_id)),
        }
    }

    pub fn expire_tcp_time_wait(
        &mut self,
        host_id: NodeId,
        local_port: u16,
    ) -> Result<(), InternetError> {
        let node = self
            .nodes
            .get_mut(&host_id)
            .ok_or(InternetError::UnknownRuntimeNode(host_id))?;
        let StackNode::Host { tcp_sockets, .. } = node else {
            return Err(InternetError::NotAHost(host_id));
        };
        let socket = tcp_sockets
            .get_mut(&local_port)
            .ok_or(InternetError::NoTcpSocket {
                node: host_id,
                port: local_port,
            })?;
        socket
            .connection
            .expire_time_wait()
            .map_err(InternetError::Tcp)
    }

    pub fn send_udp(
        &mut self,
        host_id: NodeId,
        destination: Ipv4Addr,
        datagram: UdpDatagram,
    ) -> Result<(), InternetError> {
        let source = match self
            .nodes
            .get(&host_id)
            .ok_or(InternetError::UnknownRuntimeNode(host_id))?
        {
            StackNode::Host { host, .. } => host.ip(),
            StackNode::Router { .. } => return Err(InternetError::NotAHost(host_id)),
        };
        self.send_ip(
            host_id,
            IpPacket {
                src: source,
                dst: destination,
                ttl: 64,
                payload: IpPayload::Udp(datagram),
            },
        )
    }

    // ARP 未命中不是错误：先排队 IP 包，只为第一位等待者发送一次 ARP Request。
    pub fn send_ip(&mut self, host_id: NodeId, packet: IpPacket) -> Result<(), InternetError> {
        let mut runtime = self
            .nodes
            .remove(&host_id)
            .ok_or(InternetError::UnknownRuntimeNode(host_id))?;
        let result = (|| {
            let StackNode::Host {
                host,
                arp_table,
                pending_arp,
                ..
            } = &mut runtime
            else {
                return Err(InternetError::NotAHost(host_id));
            };
            let next_hop = host.next_hop(packet.dst).ok_or(InternetError::NoRoute {
                node: host_id,
                destination: packet.dst,
            })?;
            self.trace.push(InternetTrace::HostSent {
                time_ms: self.network.now_ms,
                node: host_id,
                destination: packet.dst,
                next_hop,
            });
            if let Some(destination_mac) = arp_table.get(&next_hop).copied() {
                self.transmit(ip_frame(host_id, 0, host.mac, destination_mac, packet))
            } else {
                let first_waiter = !pending_arp.contains_key(&next_hop);
                pending_arp.entry(next_hop).or_default().push(packet);
                if first_waiter {
                    self.trace.push(InternetTrace::ArpRequest {
                        time_ms: self.network.now_ms,
                        node: host_id,
                        interface: 0,
                        target_ip: next_hop,
                    });
                    self.transmit(arp_request(host_id, 0, host.ip(), host.mac, next_hop))
                } else {
                    Ok(())
                }
            }
        })();
        self.nodes.insert(host_id, runtime);
        result
    }

    // 唯一驱动入口：Router、ARP 和 DNS 都由 FrameArrival 自动触发。
    pub fn run(&mut self) -> Result<(), InternetError> {
        while let Some(timed) = self.network.next_event() {
            match timed.event {
                NetworkEvent::FrameArrival { from, to, frame } => {
                    self.trace.push(InternetTrace::FrameArrived {
                        time_ms: timed.time_ms,
                        from,
                        to,
                        src_mac: frame.src,
                        dst_mac: frame.dst,
                    });
                    self.handle_frame(timed.time_ms, to, frame)?;
                }
                NetworkEvent::Timer { node, timer_id } => {
                    self.handle_tcp_timer(node, timer_id)?;
                }
            }
        }
        Ok(())
    }

    pub fn received_packets(&self, host: NodeId) -> Result<&[IpPacket], InternetError> {
        match self
            .nodes
            .get(&host)
            .ok_or(InternetError::UnknownRuntimeNode(host))?
        {
            StackNode::Host { inbox, .. } => Ok(inbox),
            StackNode::Router { .. } => Err(InternetError::NotAHost(host)),
        }
    }

    pub fn udp_datagrams(
        &self,
        host: NodeId,
        port: u16,
    ) -> Result<&[(Ipv4Addr, UdpDatagram)], InternetError> {
        match self
            .nodes
            .get(&host)
            .ok_or(InternetError::UnknownRuntimeNode(host))?
        {
            StackNode::Host { udp_sockets, .. } => {
                Ok(udp_sockets.get(&port).map(Vec::as_slice).unwrap_or(&[]))
            }
            StackNode::Router { .. } => Err(InternetError::NotAHost(host)),
        }
    }

    pub fn node_name(&self, id: NodeId) -> &str {
        self.network
            .node(id)
            .map(|node| node.name.as_str())
            .unwrap_or("unknown")
    }

    fn handle_frame(
        &mut self,
        time_ms: u64,
        endpoint: Endpoint,
        frame: EthernetFrame,
    ) -> Result<(), InternetError> {
        let mut runtime = self
            .nodes
            .remove(&endpoint.node)
            .ok_or(InternetError::UnknownRuntimeNode(endpoint.node))?;
        let processing = match &mut runtime {
            StackNode::Host {
                host,
                arp_table,
                pending_arp,
                inbox,
                udp_sockets,
                dns_server,
                tcp_sockets,
                http_servers,
                browser,
            } => process_host_frame(
                time_ms,
                endpoint,
                frame,
                host,
                arp_table,
                pending_arp,
                inbox,
                udp_sockets,
                dns_server,
                tcp_sockets,
                http_servers,
                browser,
            ),
            StackNode::Router {
                router,
                arp_table,
                pending_arp,
            } => process_router_frame(time_ms, endpoint, frame, router, arp_table, pending_arp),
        };
        // 错误也不能把节点从拓扑中“吃掉”。
        self.nodes.insert(endpoint.node, runtime);
        let processing = processing?;
        self.trace.extend(processing.traces);
        for frame in processing.frames {
            self.transmit(frame)?;
        }
        for packet in processing.generated_packets {
            let destination = packet.dst;
            match packet.payload {
                IpPayload::Tcp(segment) => {
                    self.send_tcp_segment(endpoint.node, destination, segment, false)?;
                }
                payload => {
                    self.send_ip(endpoint.node, IpPacket { payload, ..packet })?;
                }
            }
        }
        for action in processing.application_actions {
            self.execute_application_action(endpoint.node, action)?;
        }
        Ok(())
    }

    fn execute_application_action(
        &mut self,
        node: NodeId,
        action: ApplicationAction,
    ) -> Result<(), InternetError> {
        match action {
            ApplicationAction::TcpConnect {
                local_port,
                destination,
                remote_port,
            } => self.tcp_connect(node, local_port, destination, remote_port),
            ApplicationAction::HttpGet {
                local_port,
                host_name,
                path,
            } => self.http_get(node, local_port, &host_name, &path),
            ApplicationAction::TcpClose { local_port } => self.tcp_close(node, local_port),
            ApplicationAction::ExpireTimeWait { local_port } => {
                self.expire_tcp_time_wait(node, local_port)
            }
            ApplicationAction::DropNextFrame { from } => {
                self.network.drop_next_frame_from(from)?;
                Ok(())
            }
        }
    }

    fn send_tcp_segment(
        &mut self,
        node: NodeId,
        destination: Ipv4Addr,
        segment: TcpSegment,
        retransmission: bool,
    ) -> Result<(), InternetError> {
        let source = match self
            .nodes
            .get(&node)
            .ok_or(InternetError::UnknownRuntimeNode(node))?
        {
            StackNode::Host { host, .. } => host.ip(),
            StackNode::Router { .. } => return Err(InternetError::NotAHost(node)),
        };
        self.trace.push(InternetTrace::TcpSent {
            time_ms: self.network.now_ms,
            node,
            destination,
            segment: segment.clone(),
            retransmission,
        });
        self.send_ip(
            node,
            IpPacket {
                src: source,
                dst: destination,
                ttl: 64,
                payload: IpPayload::Tcp(segment.clone()),
            },
        )?;
        if segment.sequence_len() > 0 {
            self.arm_tcp_timer(node, destination, segment)?;
        }
        Ok(())
    }

    fn arm_tcp_timer(
        &mut self,
        node: NodeId,
        destination: Ipv4Addr,
        segment: TcpSegment,
    ) -> Result<(), InternetError> {
        let timer_id = self.next_timer_id;
        self.next_timer_id += 1;
        self.tcp_timers.insert(
            timer_id,
            TcpTimer {
                node,
                local_port: segment.src_port,
                destination,
                segment,
            },
        );
        self.network
            .schedule_timer(node, timer_id, self.tcp_rto_ms)?;
        Ok(())
    }

    fn handle_tcp_timer(&mut self, node: NodeId, timer_id: u64) -> Result<(), InternetError> {
        let Some(timer) = self.tcp_timers.remove(&timer_id) else {
            return Ok(());
        };
        if timer.node != node {
            return Ok(());
        }
        let still_unacked = match self.nodes.get(&node) {
            Some(StackNode::Host { tcp_sockets, .. }) => tcp_sockets
                .get(&timer.local_port)
                .is_some_and(|socket| socket.connection.unacked.contains_key(&timer.segment.seq)),
            _ => false,
        };
        if !still_unacked {
            return Ok(());
        }
        self.trace.push(InternetTrace::TcpTimeout {
            time_ms: self.network.now_ms,
            node,
            local_port: timer.local_port,
            seq: timer.segment.seq,
        });
        self.send_tcp_segment(node, timer.destination, timer.segment, true)
    }

    fn transmit(&mut self, outgoing: OutgoingFrame) -> Result<(), InternetError> {
        match self.network.send_frame(outgoing.from, outgoing.frame)? {
            SendDisposition::Scheduled { .. } => Ok(()),
            SendDisposition::Dropped { destination } => {
                self.trace.push(InternetTrace::LinkDropped {
                    time_ms: self.network.now_ms,
                    from: outgoing.from,
                    destination,
                });
                Ok(())
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn process_host_frame(
    time_ms: u64,
    endpoint: Endpoint,
    frame: EthernetFrame,
    host: &Host,
    arp_table: &mut HashMap<Ipv4Addr, MacAddr>,
    pending_arp: &mut HashMap<Ipv4Addr, Vec<IpPacket>>,
    inbox: &mut Vec<IpPacket>,
    udp_sockets: &mut HashMap<u16, Vec<(Ipv4Addr, UdpDatagram)>>,
    dns_server: &Option<DnsServer>,
    tcp_sockets: &mut HashMap<u16, TcpSocket>,
    http_servers: &HashMap<u16, HttpServer>,
    browser: &mut Option<BrowserRuntime>,
) -> Result<NodeProcessing, InternetError> {
    let mut result = NodeProcessing::new();
    if endpoint.interface != 0 || (frame.dst != host.mac && frame.dst != MacAddr::broadcast()) {
        return Ok(result);
    }
    match frame.payload {
        EthernetPayload::Arp(arp) => {
            arp_table.insert(arp.sender_ip, arp.sender_mac);
            result.traces.push(InternetTrace::ArpLearned {
                time_ms,
                node: endpoint.node,
                interface: 0,
                ip: arp.sender_ip,
                mac: arp.sender_mac,
            });
            if arp.request && arp.target_ip == host.ip() {
                result.traces.push(InternetTrace::ArpReply {
                    time_ms,
                    node: endpoint.node,
                    interface: 0,
                    target_ip: arp.sender_ip,
                });
                result
                    .frames
                    .push(arp_reply(endpoint.node, 0, host.ip(), host.mac, &arp));
            } else if !arp.request
                && arp.target_ip == host.ip()
                && let Some(waiting) = pending_arp.remove(&arp.sender_ip)
            {
                for packet in waiting {
                    result.frames.push(ip_frame(
                        endpoint.node,
                        0,
                        host.mac,
                        arp.sender_mac,
                        packet,
                    ));
                }
            }
        }
        EthernetPayload::Ip(packet) if packet.dst == host.ip() && frame.dst == host.mac => {
            inbox.push(packet.clone());
            result.traces.push(InternetTrace::HostReceived {
                time_ms,
                node: endpoint.node,
                packet: packet.clone(),
            });
            match &packet.payload {
                IpPayload::Udp(datagram) => {
                    result.traces.push(InternetTrace::UdpDelivered {
                        time_ms,
                        node: endpoint.node,
                        src_port: datagram.src_port,
                        dst_port: datagram.dst_port,
                    });
                    if datagram.dst_port == DNS_PORT && dns_server.is_some() {
                        let server = dns_server.as_ref().expect("已经检查 DNS Server 存在");
                        let response = server.handle_udp(datagram)?;
                        let UdpPayload::Dns(query) = &datagram.payload;
                        result.traces.push(InternetTrace::DnsAnswered {
                            time_ms,
                            node: endpoint.node,
                            client: packet.src,
                            query_id: query.id,
                        });
                        result.generated_packets.push(IpPacket {
                            src: host.ip(),
                            dst: packet.src,
                            ttl: 64,
                            payload: IpPayload::Udp(response),
                        });
                    } else if !process_browser_dns_response(
                        time_ms,
                        endpoint.node,
                        datagram,
                        browser,
                        &mut result,
                    )? {
                        udp_sockets
                            .entry(datagram.dst_port)
                            .or_default()
                            .push((packet.src, datagram.clone()));
                    }
                }
                IpPayload::Tcp(segment) => process_tcp_on_host(
                    time_ms,
                    endpoint.node,
                    host.ip(),
                    packet.src,
                    segment,
                    tcp_sockets,
                    http_servers,
                    browser,
                    &mut result,
                )?,
                _ => {}
            }
        }
        _ => {}
    }
    Ok(result)
}

fn process_browser_dns_response(
    time_ms: u64,
    node: NodeId,
    datagram: &UdpDatagram,
    browser: &mut Option<BrowserRuntime>,
    result: &mut NodeProcessing,
) -> Result<bool, InternetError> {
    let Some(browser) = browser.as_mut() else {
        return Ok(false);
    };
    if browser.state != BrowserState::Resolving || datagram.dst_port != browser.dns_port {
        return Ok(false);
    }
    let UdpPayload::Dns(response) = &datagram.payload;
    if !response.is_response {
        return Ok(false);
    }
    let address = response
        .answers
        .iter()
        .find_map(|record| match record.data {
            DnsRecordData::A(ip) if record.name == browser.host_name => Some(ip),
            _ => None,
        })
        .ok_or_else(|| DnsResolveError::NoAnswer(browser.host_name.clone()))?;
    browser.state = BrowserState::Connecting;
    result.traces.push(InternetTrace::BrowserResolved {
        time_ms,
        node,
        host_name: browser.host_name.clone(),
        address,
    });
    result
        .application_actions
        .push(ApplicationAction::TcpConnect {
            local_port: browser.tcp_port,
            destination: address,
            remote_port: 80,
        });
    Ok(true)
}

#[allow(clippy::too_many_arguments)]
fn process_tcp_on_host(
    time_ms: u64,
    node: NodeId,
    local_ip: Ipv4Addr,
    source_ip: Ipv4Addr,
    segment: &TcpSegment,
    tcp_sockets: &mut HashMap<u16, TcpSocket>,
    http_servers: &HashMap<u16, HttpServer>,
    browser: &mut Option<BrowserRuntime>,
    result: &mut NodeProcessing,
) -> Result<(), InternetError> {
    let Some(socket) = tcp_sockets.get_mut(&segment.dst_port) else {
        return Ok(()); // 未监听端口在这个教学版本中静默丢弃，后续可扩展 RST。
    };
    if socket.remote_ip.is_none() && socket.connection.state == TcpState::Listen {
        socket.remote_ip = Some(source_ip);
    }
    if socket.remote_ip != Some(source_ip) {
        return Ok(());
    }

    result.traces.push(InternetTrace::TcpReceived {
        time_ms,
        node,
        source: source_ip,
        segment: segment.clone(),
    });
    let old_state = socket.connection.state;
    let reply = socket
        .connection
        .receive(segment.clone())
        .map_err(InternetError::Tcp)?;
    if old_state != socket.connection.state {
        result.traces.push(InternetTrace::TcpStateChanged {
            time_ms,
            node,
            local_port: segment.dst_port,
            old: old_state,
            new: socket.connection.state,
        });
        if let Some(browser) = browser.as_mut() {
            if segment.dst_port == browser.tcp_port
                && browser.state == BrowserState::Connecting
                && socket.connection.state == TcpState::Established
            {
                browser.state = BrowserState::Requesting;
                if let Some(from) = browser.drop_http_at.take() {
                    result
                        .application_actions
                        .push(ApplicationAction::DropNextFrame { from });
                }
                result.application_actions.push(ApplicationAction::HttpGet {
                    local_port: browser.tcp_port,
                    host_name: browser.host_name.clone(),
                    path: browser.path.clone(),
                });
            } else if segment.dst_port == browser.tcp_port
                && browser.state == BrowserState::Closing
                && socket.connection.state == TcpState::TimeWait
            {
                browser.state = BrowserState::Complete;
                result
                    .application_actions
                    .push(ApplicationAction::ExpireTimeWait {
                        local_port: browser.tcp_port,
                    });
            }
        }
    }
    if let Some(reply) = reply {
        result
            .generated_packets
            .push(tcp_packet(local_ip, source_ip, reply));
    }

    // HTTP Server 只在 TCP 把完整请求字节交给应用后工作；它看不到 IP/ARP。
    if !segment.payload.is_empty()
        && let Some(server) = http_servers.get(&segment.dst_port)
    {
        let bytes = socket.connection.application_read(usize::MAX);
        if !bytes.is_empty() {
            let request = HttpRequest::parse(&bytes).map_err(InternetError::Http)?;
            let response = server.handle(&request);
            result.traces.push(InternetTrace::HttpHandled {
                time_ms,
                node,
                path: request.path,
                status_code: response.status_code,
            });
            let segments = socket
                .connection
                .send_data(&response.to_bytes(), 1460)
                .map_err(InternetError::Tcp)?;
            for response_segment in segments {
                result
                    .generated_packets
                    .push(tcp_packet(local_ip, source_ip, response_segment));
            }
        }
    }

    // Browser 收到 HTTP 字节后自行解析并触发关闭；Demo 不参与协议推进。
    if !segment.payload.is_empty()
        && let Some(browser) = browser.as_mut()
        && segment.dst_port == browser.tcp_port
        && browser.state == BrowserState::Requesting
    {
        let bytes = socket.connection.application_read(usize::MAX);
        if !bytes.is_empty() {
            let response = HttpResponse::parse(&bytes).map_err(InternetError::Http)?;
            result.traces.push(InternetTrace::BrowserRendered {
                time_ms,
                node,
                status_code: response.status_code,
            });
            browser.response = Some(response);
            browser.state = BrowserState::Closing;
            result
                .application_actions
                .push(ApplicationAction::TcpClose {
                    local_port: browser.tcp_port,
                });
        }
    }

    // HTTP Server 主动完成被动关闭：先 ACK 客户端 FIN，再发自己的 FIN。
    if socket.connection.state == TcpState::CloseWait {
        let old = socket.connection.state;
        let fin = socket.connection.close().map_err(InternetError::Tcp)?;
        result.traces.push(InternetTrace::TcpStateChanged {
            time_ms,
            node,
            local_port: segment.dst_port,
            old,
            new: socket.connection.state,
        });
        result
            .generated_packets
            .push(tcp_packet(local_ip, source_ip, fin));
    }
    Ok(())
}

fn tcp_packet(source: Ipv4Addr, destination: Ipv4Addr, segment: TcpSegment) -> IpPacket {
    IpPacket {
        src: source,
        dst: destination,
        ttl: 64,
        payload: IpPayload::Tcp(segment),
    }
}

fn parse_http_url(url: &str) -> Result<(String, String), InternetError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| InternetError::InvalidUrl(url.to_string()))?;
    if rest.is_empty() {
        return Err(InternetError::InvalidUrl(url.to_string()));
    }
    let (host, path) = match rest.split_once('/') {
        Some((host, path)) if !host.is_empty() => (host, format!("/{path}")),
        None => (rest, "/".to_string()),
        _ => return Err(InternetError::InvalidUrl(url.to_string())),
    };
    Ok((host.to_ascii_lowercase(), path))
}

fn process_router_frame(
    time_ms: u64,
    endpoint: Endpoint,
    frame: EthernetFrame,
    router: &Router,
    arp_table: &mut HashMap<(usize, Ipv4Addr), MacAddr>,
    pending_arp: &mut HashMap<(usize, Ipv4Addr), Vec<IpPacket>>,
) -> Result<NodeProcessing, InternetError> {
    let mut result = NodeProcessing::new();
    let interface = router
        .interfaces
        .get(endpoint.interface)
        .ok_or(InternetError::InvalidInterface(endpoint))?;
    if frame.dst != interface.mac && frame.dst != MacAddr::broadcast() {
        return Ok(result);
    }
    match frame.payload {
        EthernetPayload::Arp(arp) => {
            let key = (endpoint.interface, arp.sender_ip);
            arp_table.insert(key, arp.sender_mac);
            result.traces.push(InternetTrace::ArpLearned {
                time_ms,
                node: endpoint.node,
                interface: endpoint.interface,
                ip: arp.sender_ip,
                mac: arp.sender_mac,
            });
            if arp.request && arp.target_ip == interface.ip {
                result.traces.push(InternetTrace::ArpReply {
                    time_ms,
                    node: endpoint.node,
                    interface: endpoint.interface,
                    target_ip: arp.sender_ip,
                });
                result.frames.push(arp_reply(
                    endpoint.node,
                    endpoint.interface,
                    interface.ip,
                    interface.mac,
                    &arp,
                ));
            } else if !arp.request
                && arp.target_ip == interface.ip
                && let Some(waiting) = pending_arp.remove(&key)
            {
                for packet in waiting {
                    result.frames.push(ip_frame(
                        endpoint.node,
                        endpoint.interface,
                        interface.mac,
                        arp.sender_mac,
                        packet,
                    ));
                }
            }
        }
        EthernetPayload::Ip(packet) if frame.dst == interface.mac => {
            match router.receive_ip(endpoint.interface, packet) {
                RouterAction::Forward {
                    packet,
                    next_hop,
                    iface,
                    src_mac,
                } => {
                    let ttl = packet.ttl;
                    result.traces.push(InternetTrace::RouterForwarded {
                        time_ms,
                        node: endpoint.node,
                        incoming_iface: endpoint.interface,
                        outgoing_iface: iface,
                        next_hop,
                        ttl,
                    });
                    queue_or_send_router(
                        time_ms,
                        endpoint.node,
                        router,
                        arp_table,
                        pending_arp,
                        iface,
                        next_hop,
                        src_mac,
                        packet,
                        &mut result,
                    )?;
                }
                RouterAction::Reply {
                    packet,
                    next_hop,
                    iface,
                    src_mac,
                } => {
                    result.traces.push(InternetTrace::RouterReplied {
                        time_ms,
                        node: endpoint.node,
                        outgoing_iface: iface,
                        next_hop,
                    });
                    queue_or_send_router(
                        time_ms,
                        endpoint.node,
                        router,
                        arp_table,
                        pending_arp,
                        iface,
                        next_hop,
                        src_mac,
                        packet,
                        &mut result,
                    )?;
                }
                RouterAction::Drop { reason } => result.traces.push(InternetTrace::RouterDropped {
                    time_ms,
                    node: endpoint.node,
                    reason,
                }),
            }
        }
        _ => {}
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn queue_or_send_router(
    time_ms: u64,
    node: NodeId,
    router: &Router,
    arp_table: &HashMap<(usize, Ipv4Addr), MacAddr>,
    pending_arp: &mut HashMap<(usize, Ipv4Addr), Vec<IpPacket>>,
    iface: usize,
    next_hop: Ipv4Addr,
    src_mac: MacAddr,
    packet: IpPacket,
    result: &mut NodeProcessing,
) -> Result<(), InternetError> {
    let interface = router
        .interfaces
        .get(iface)
        .ok_or(InternetError::InvalidInterface(Endpoint {
            node,
            interface: iface,
        }))?;
    let key = (iface, next_hop);
    if let Some(destination_mac) = arp_table.get(&key).copied() {
        result
            .frames
            .push(ip_frame(node, iface, src_mac, destination_mac, packet));
    } else {
        let first_waiter = !pending_arp.contains_key(&key);
        pending_arp.entry(key).or_default().push(packet);
        if first_waiter {
            result.traces.push(InternetTrace::ArpRequest {
                time_ms,
                node,
                interface: iface,
                target_ip: next_hop,
            });
            result.frames.push(arp_request(
                node,
                iface,
                interface.ip,
                interface.mac,
                next_hop,
            ));
        }
    }
    Ok(())
}

fn arp_request(
    node: NodeId,
    interface: usize,
    sender_ip: Ipv4Addr,
    sender_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> OutgoingFrame {
    OutgoingFrame {
        from: Endpoint { node, interface },
        frame: EthernetFrame {
            src: sender_mac,
            dst: MacAddr::broadcast(),
            payload: EthernetPayload::Arp(ArpPacket {
                request: true,
                sender_ip,
                sender_mac,
                target_ip,
                target_mac: None,
            }),
        },
    }
}

fn arp_reply(
    node: NodeId,
    interface: usize,
    sender_ip: Ipv4Addr,
    sender_mac: MacAddr,
    request: &ArpPacket,
) -> OutgoingFrame {
    OutgoingFrame {
        from: Endpoint { node, interface },
        frame: EthernetFrame {
            src: sender_mac,
            dst: request.sender_mac,
            payload: EthernetPayload::Arp(ArpPacket {
                request: false,
                sender_ip,
                sender_mac,
                target_ip: request.sender_ip,
                target_mac: Some(request.sender_mac),
            }),
        },
    }
}

fn ip_frame(
    node: NodeId,
    interface: usize,
    source_mac: MacAddr,
    destination_mac: MacAddr,
    packet: IpPacket,
) -> OutgoingFrame {
    OutgoingFrame {
        from: Endpoint { node, interface },
        frame: EthernetFrame {
            src: source_mac,
            dst: destination_mac,
            payload: EthernetPayload::Ip(packet),
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::dns::{DnsMessage, DnsRecord, DnsRecordData, DnsRecordType};
    use crate::routing::{Interface, RoutingTable};

    use super::*;

    struct Lab {
        internet: MiniInternet,
        a: NodeId,
        b: NodeId,
        a_ip: Ipv4Addr,
        b_ip: Ipv4Addr,
    }

    fn two_lans() -> Lab {
        let mask = Ipv4Addr { value: 0xFFFF_FF00 };
        let a_ip = Ipv4Addr { value: 0xC0A8_0102 };
        let b_ip = Ipv4Addr { value: 0x0A00_0002 };
        let left_ip = Ipv4Addr { value: 0xC0A8_0101 };
        let right_ip = Ipv4Addr { value: 0x0A00_0001 };
        let mut a_routes = RoutingTable::new();
        a_routes.add_direct_route(0, a_ip, mask);
        a_routes.add_default_route(0, left_ip);
        let a_host = Host::new("A", a_ip, mask, a_routes, MacAddr::new([2, 0, 0, 0, 1, 2]));
        let mut b_routes = RoutingTable::new();
        b_routes.add_direct_route(0, b_ip, mask);
        b_routes.add_default_route(0, right_ip);
        let b_host = Host::new("B", b_ip, mask, b_routes, MacAddr::new([2, 0, 0, 0, 2, 2]));
        let left = Interface::new("left", left_ip, mask, MacAddr::new([2, 0, 0, 0, 1, 1]));
        let right = Interface::new("right", right_ip, mask, MacAddr::new([2, 0, 0, 0, 2, 1]));
        let mut routes = RoutingTable::new();
        routes.add_direct_route(0, left_ip, mask);
        routes.add_direct_route(1, right_ip, mask);
        let router = Router::new("R1", vec![left, right], routes);
        let mut internet = MiniInternet::new();
        let a = internet.add_host(a_host);
        let r = internet.add_router(router);
        let b = internet.add_host(b_host);
        internet
            .connect(
                Endpoint {
                    node: a,
                    interface: 0,
                },
                Endpoint {
                    node: r,
                    interface: 0,
                },
                5,
                0,
            )
            .unwrap();
        internet
            .connect(
                Endpoint {
                    node: r,
                    interface: 1,
                },
                Endpoint {
                    node: b,
                    interface: 0,
                },
                5,
                0,
            )
            .unwrap();
        Lab {
            internet,
            a,
            b,
            a_ip,
            b_ip,
        }
    }

    #[test]
    fn arp_miss_resolves_and_releases_waiting_ip_packet() {
        let mut lab = two_lans();
        lab.internet
            .send_ip(
                lab.a,
                IpPacket {
                    src: lab.a_ip,
                    dst: lab.b_ip,
                    ttl: 64,
                    payload: IpPayload::Data("dynamic ARP".into()),
                },
            )
            .unwrap();
        lab.internet.run().unwrap();
        let received = lab.internet.received_packets(lab.b).unwrap();
        assert_eq!(received.len(), 1);
        assert_eq!(received[0].ttl, 63);
        assert_eq!(
            lab.internet
                .trace
                .iter()
                .filter(|event| matches!(event, InternetTrace::ArpRequest { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn dns_query_reaches_udp_53_and_response_returns() {
        let mut lab = two_lans();
        lab.internet
            .bind_dns_server(
                lab.b,
                DnsServer::new(
                    "ns.tinynet",
                    lab.b_ip,
                    vec![DnsRecord::a(
                        "www.tinynet.com",
                        Ipv4Addr { value: 0x0A00_0063 },
                        300,
                    )],
                ),
            )
            .unwrap();
        lab.internet
            .send_udp(
                lab.a,
                lab.b_ip,
                UdpDatagram {
                    src_port: 53_000,
                    dst_port: DNS_PORT,
                    payload: UdpPayload::Dns(DnsMessage::query(
                        7,
                        "www.tinynet.com",
                        DnsRecordType::A,
                    )),
                },
            )
            .unwrap();
        lab.internet.run().unwrap();
        let responses = lab.internet.udp_datagrams(lab.a, 53_000).unwrap();
        assert_eq!(responses.len(), 1);
        let UdpPayload::Dns(message) = &responses[0].1.payload;
        assert!(message.is_response);
        assert!(matches!(
            message.answers[0].data,
            DnsRecordData::A(Ipv4Addr { value: 0x0A00_0063 })
        ));
    }

    #[test]
    fn tcp_http_retransmits_dropped_data_and_closes_cleanly() {
        let mut lab = two_lans();
        let mut server = HttpServer::new("www.tinynet.com");
        server.add_resource("/index.html", "<h1>TinyNet</h1>");
        lab.internet.bind_http_server(lab.b, 80, server).unwrap();

        lab.internet
            .tcp_connect(lab.a, 50_000, lab.b_ip, 80)
            .unwrap();
        lab.internet.run().unwrap();
        assert_eq!(
            lab.internet.tcp_state(lab.a, 50_000).unwrap(),
            TcpState::Established
        );
        assert_eq!(
            lab.internet.tcp_state(lab.b, 80).unwrap(),
            TcpState::Established
        );

        // 握手和 ARP 已完成，只丢客户端发出的下一帧（即 HTTP 请求数据）。
        lab.internet
            .network
            .drop_next_frame_from(Endpoint {
                node: lab.a,
                interface: 0,
            })
            .unwrap();
        lab.internet
            .http_get(lab.a, 50_000, "www.tinynet.com", "/index.html")
            .unwrap();
        lab.internet.run().unwrap();
        let response = lab.internet.read_http_response(lab.a, 50_000).unwrap();
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, "<h1>TinyNet</h1>");
        assert!(lab.internet.trace.iter().any(|event| matches!(
            event,
            InternetTrace::TcpTimeout {
                node,
                local_port: 50_000,
                ..
            } if *node == lab.a
        )));

        lab.internet.tcp_close(lab.a, 50_000).unwrap();
        lab.internet.run().unwrap();
        assert_eq!(
            lab.internet.tcp_state(lab.a, 50_000).unwrap(),
            TcpState::TimeWait
        );
        assert_eq!(lab.internet.tcp_state(lab.b, 80).unwrap(), TcpState::Closed);
        lab.internet.expire_tcp_time_wait(lab.a, 50_000).unwrap();
        assert_eq!(
            lab.internet.tcp_state(lab.a, 50_000).unwrap(),
            TcpState::Closed
        );
    }

    #[test]
    fn browser_open_drives_dns_tcp_http_and_close_from_event_callbacks() {
        let mut lab = two_lans();
        lab.internet
            .bind_dns_server(
                lab.b,
                DnsServer::new(
                    "DNS",
                    lab.b_ip,
                    vec![DnsRecord::a("www.tinynet.com", lab.b_ip, 300)],
                ),
            )
            .unwrap();
        let mut http = HttpServer::new("www.tinynet.com");
        http.add_resource("/index.html", "<h1>Hello TinyNet!</h1>");
        lab.internet.bind_http_server(lab.b, 80, http).unwrap();
        let browser = lab.internet.install_browser(lab.a, lab.b_ip).unwrap();
        // DNS 完成后、HTTP GET 发出前，状态机会自动启用这个一次性故障。
        lab.internet
            .drop_browser_http_once_at(
                lab.a,
                Endpoint {
                    node: lab.a,
                    interface: 0,
                },
            )
            .unwrap();

        browser
            .open(&mut lab.internet, "http://www.tinynet.com/index.html")
            .unwrap();
        lab.internet.run().unwrap();

        assert_eq!(
            browser.state(&lab.internet).unwrap(),
            BrowserState::Complete
        );
        let response = browser.response(&lab.internet).unwrap().unwrap();
        assert_eq!(response.status_code, 200);
        assert_eq!(response.body, "<h1>Hello TinyNet!</h1>");
        assert!(lab.internet.trace.iter().any(|event| matches!(
            event,
            InternetTrace::TcpTimeout {
                node,
                local_port: 50_000,
                ..
            } if *node == lab.a
        )));
        assert_eq!(
            lab.internet.tcp_state(lab.a, 50_000).unwrap(),
            TcpState::Closed
        );
        assert_eq!(lab.internet.tcp_state(lab.b, 80).unwrap(), TcpState::Closed);
    }
}
