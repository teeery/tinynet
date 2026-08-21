use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};

use crate::packet::EthernetFrame;

// ========== v1.0：Network Simulation Engine ==========
//
// 第一个检查点只负责“拓扑 + 时间 + 帧投递”。Network 不解释 ARP/IP/TCP，
// 就像真实网线不会理解帧里的上层协议一样。
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Host,
    Router,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo {
    pub id: NodeId,
    pub name: String,
    pub kind: NodeKind,
    pub interface_count: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub node: NodeId,
    pub interface: usize,
}

#[derive(Clone, Debug)]
pub struct Link {
    pub endpoint_a: Endpoint,
    pub endpoint_b: Endpoint,
    pub delay_ms: u64,
    pub loss_percent: u8,
    random_state: u64,
    // 教学实验可指定某个方向的“下一帧必丢”，用于稳定复现超时重传。
    drop_next_from: Option<Endpoint>,
}

impl Link {
    fn peer(&self, endpoint: Endpoint) -> Option<Endpoint> {
        if endpoint == self.endpoint_a {
            Some(self.endpoint_b)
        } else if endpoint == self.endpoint_b {
            Some(self.endpoint_a)
        } else {
            None
        }
    }

    fn should_drop(&mut self) -> bool {
        self.random_state = self
            .random_state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        ((self.random_state >> 32) % 100) < u64::from(self.loss_percent)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkEvent {
    FrameArrival {
        from: Endpoint,
        to: Endpoint,
        frame: EthernetFrame,
    },
    // Network 不解释 timer_id；TCP 等上层协议负责赋予它含义。
    Timer {
        node: NodeId,
        timer_id: u64,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimedEvent {
    pub time_ms: u64,
    pub event: NetworkEvent,
}

// BinaryHeap 默认先弹最大值，因此比较时反转 time/order，得到最早事件优先。
#[derive(Clone, Debug, PartialEq, Eq)]
struct ScheduledEvent {
    time_ms: u64,
    order: u64,
    event: NetworkEvent,
}

impl Ord for ScheduledEvent {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .time_ms
            .cmp(&self.time_ms)
            .then_with(|| other.order.cmp(&self.order))
    }
}

impl PartialOrd for ScheduledEvent {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendDisposition {
    Scheduled {
        destination: Endpoint,
        arrival_time_ms: u64,
    },
    Dropped {
        destination: Endpoint,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkError {
    UnknownNode(NodeId),
    InvalidInterface(Endpoint),
    EndpointAlreadyConnected(Endpoint),
    NoLink(Endpoint),
    InvalidLossPercent(u8),
}

pub struct Network {
    pub now_ms: u64,
    nodes: HashMap<NodeId, NodeInfo>,
    links: Vec<Link>,
    events: BinaryHeap<ScheduledEvent>,
    next_node_id: u32,
    next_event_order: u64,
}

impl Network {
    pub fn new() -> Self {
        Self {
            now_ms: 0,
            nodes: HashMap::new(),
            links: Vec::new(),
            events: BinaryHeap::new(),
            next_node_id: 1,
            next_event_order: 0,
        }
    }

    pub fn add_node(&mut self, name: &str, kind: NodeKind, interface_count: usize) -> NodeId {
        let id = NodeId(self.next_node_id);
        self.next_node_id += 1;
        self.nodes.insert(
            id,
            NodeInfo {
                id,
                name: name.to_string(),
                kind,
                interface_count,
            },
        );
        id
    }

    pub fn node(&self, id: NodeId) -> Option<&NodeInfo> {
        self.nodes.get(&id)
    }

    pub fn connect(
        &mut self,
        endpoint_a: Endpoint,
        endpoint_b: Endpoint,
        delay_ms: u64,
        loss_percent: u8,
    ) -> Result<(), NetworkError> {
        self.validate_endpoint(endpoint_a)?;
        self.validate_endpoint(endpoint_b)?;
        if loss_percent > 100 {
            return Err(NetworkError::InvalidLossPercent(loss_percent));
        }
        for endpoint in [endpoint_a, endpoint_b] {
            if self.links.iter().any(|link| link.peer(endpoint).is_some()) {
                return Err(NetworkError::EndpointAlreadyConnected(endpoint));
            }
        }
        // 使用端点信息作为种子，使相同拓扑的丢包实验可复现。
        let seed = u64::from(endpoint_a.node.0) << 32
            ^ u64::from(endpoint_b.node.0)
            ^ endpoint_a.interface as u64
            ^ (endpoint_b.interface as u64) << 16;
        self.links.push(Link {
            endpoint_a,
            endpoint_b,
            delay_ms,
            loss_percent,
            random_state: seed,
            drop_next_from: None,
        });
        Ok(())
    }

    // 节点只说“从哪个接口发帧”。Network 根据 Link 自动找到对端并排队。
    pub fn send_frame(
        &mut self,
        from: Endpoint,
        frame: EthernetFrame,
    ) -> Result<SendDisposition, NetworkError> {
        self.validate_endpoint(from)?;
        let link_index = self
            .links
            .iter()
            .position(|link| link.peer(from).is_some())
            .ok_or(NetworkError::NoLink(from))?;
        let link = &mut self.links[link_index];
        let destination = link.peer(from).expect("已经找到包含该端点的 Link");
        let forced_drop = link.drop_next_from == Some(from);
        if forced_drop {
            link.drop_next_from = None;
        }
        if forced_drop || link.should_drop() {
            return Ok(SendDisposition::Dropped { destination });
        }

        let arrival_time_ms = self.now_ms + link.delay_ms;
        self.events.push(ScheduledEvent {
            time_ms: arrival_time_ms,
            order: self.next_event_order,
            event: NetworkEvent::FrameArrival {
                from,
                to: destination,
                frame,
            },
        });
        self.next_event_order += 1;
        Ok(SendDisposition::Scheduled {
            destination,
            arrival_time_ms,
        })
    }

    // 指定方向下一帧必丢。调用方通常在 ARP/握手完成后启用它。
    pub fn drop_next_frame_from(&mut self, from: Endpoint) -> Result<(), NetworkError> {
        self.validate_endpoint(from)?;
        let link = self
            .links
            .iter_mut()
            .find(|link| link.peer(from).is_some())
            .ok_or(NetworkError::NoLink(from))?;
        link.drop_next_from = Some(from);
        Ok(())
    }

    pub fn schedule_timer(
        &mut self,
        node: NodeId,
        timer_id: u64,
        delay_ms: u64,
    ) -> Result<(), NetworkError> {
        if !self.nodes.contains_key(&node) {
            return Err(NetworkError::UnknownNode(node));
        }
        self.events.push(ScheduledEvent {
            time_ms: self.now_ms + delay_ms,
            order: self.next_event_order,
            event: NetworkEvent::Timer { node, timer_id },
        });
        self.next_event_order += 1;
        Ok(())
    }

    pub fn next_event(&mut self) -> Option<TimedEvent> {
        let scheduled = self.events.pop()?;
        self.now_ms = scheduled.time_ms;
        Some(TimedEvent {
            time_ms: scheduled.time_ms,
            event: scheduled.event,
        })
    }

    pub fn run(&mut self) -> Vec<TimedEvent> {
        let mut delivered = Vec::new();
        while let Some(event) = self.next_event() {
            delivered.push(event);
        }
        delivered
    }

    pub fn pending_events(&self) -> usize {
        self.events.len()
    }

    fn validate_endpoint(&self, endpoint: Endpoint) -> Result<(), NetworkError> {
        let node = self
            .nodes
            .get(&endpoint.node)
            .ok_or(NetworkError::UnknownNode(endpoint.node))?;
        if endpoint.interface >= node.interface_count {
            return Err(NetworkError::InvalidInterface(endpoint));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::address::{Ipv4Addr, MacAddr};
    use crate::packet::{EthernetPayload, IpPacket, IpPayload};

    use super::*;

    fn frame() -> EthernetFrame {
        EthernetFrame {
            src: MacAddr::new([0x02, 0, 0, 0, 0, 1]),
            dst: MacAddr::new([0x02, 0, 0, 0, 0, 2]),
            payload: EthernetPayload::Ip(IpPacket {
                src: Ipv4Addr { value: 0xC0A8_0102 },
                dst: Ipv4Addr { value: 0xC0A8_0101 },
                ttl: 64,
                payload: IpPayload::Data("hello link".to_string()),
            }),
        }
    }

    #[test]
    fn frame_arrives_at_link_peer_after_delay() {
        let mut network = Network::new();
        let host = network.add_node("A", NodeKind::Host, 1);
        let router = network.add_node("R1", NodeKind::Router, 2);
        let from = Endpoint {
            node: host,
            interface: 0,
        };
        let to = Endpoint {
            node: router,
            interface: 0,
        };
        network.connect(from, to, 12, 0).unwrap();

        assert_eq!(
            network.send_frame(from, frame()).unwrap(),
            SendDisposition::Scheduled {
                destination: to,
                arrival_time_ms: 12,
            }
        );
        let event = network.next_event().unwrap();
        assert_eq!(event.time_ms, 12);
        assert!(matches!(
            event.event,
            NetworkEvent::FrameArrival { from: actual_from, to: actual_to, .. }
                if actual_from == from && actual_to == to
        ));
    }

    #[test]
    fn link_can_drop_frames_before_they_enter_event_queue() {
        let mut network = Network::new();
        let a = network.add_node("A", NodeKind::Host, 1);
        let b = network.add_node("B", NodeKind::Host, 1);
        let from = Endpoint {
            node: a,
            interface: 0,
        };
        let to = Endpoint {
            node: b,
            interface: 0,
        };
        network.connect(from, to, 5, 100).unwrap();

        assert_eq!(
            network.send_frame(from, frame()).unwrap(),
            SendDisposition::Dropped { destination: to }
        );
        assert_eq!(network.pending_events(), 0);
    }
}
