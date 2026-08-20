use crate::address::Ipv4Addr;
use crate::host::Host;
use crate::icmp::IcmpMessage;
use crate::packet::IpPayload;
use crate::routing::{Router, RouterAction, RouterDropReason};

// 路径中的一个 Router，以及探测包从哪个接口进入它。
// v0.6 用显式路径代替完整事件队列，让重点保持在 TTL 和 ICMP 上。
pub struct TraceRouter<'a> {
    pub router: &'a Router,
    pub incoming_iface: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceOutcome {
    TimeExceeded,
    ReachedDestination,
    DestinationUnreachable,
    Dropped(RouterDropReason),
    Timeout,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceHop {
    pub ttl: u8,
    pub responder: Option<Ipv4Addr>,
    pub outcome: TraceOutcome,
}

// traceroute 的本质：从 TTL=1 开始重复发送 Echo Request。
// 哪一台 Router 把 TTL 减到不能继续转发，哪一台就返回 Time Exceeded；
// 当探测包最终到达目标 Host 时，Echo Reply 表示追踪完成。
pub fn trace_route(
    source: &Host,
    destination: &Host,
    destination_ip: Ipv4Addr,
    path: &[TraceRouter<'_>],
    max_hops: u8,
) -> Vec<TraceHop> {
    let mut result = Vec::new();

    'probe: for ttl in 1..=max_hops {
        let mut packet = source.create_ping_packet(destination_ip, u16::from(ttl));
        packet.ttl = ttl;

        for trace_router in path {
            match trace_router
                .router
                .receive_ip(trace_router.incoming_iface, packet)
            {
                RouterAction::Forward {
                    packet: forwarded, ..
                } => packet = forwarded,
                RouterAction::Reply { packet: reply, .. } => {
                    let outcome = match &reply.payload {
                        IpPayload::Icmp(icmp) => match icmp.message {
                            IcmpMessage::TimeExceeded { .. } => TraceOutcome::TimeExceeded,
                            IcmpMessage::DestinationUnreachable { .. } => {
                                TraceOutcome::DestinationUnreachable
                            }
                            _ => TraceOutcome::Timeout,
                        },
                        IpPayload::Data(_) => TraceOutcome::Timeout,
                    };
                    result.push(TraceHop {
                        ttl,
                        responder: Some(reply.src),
                        outcome,
                    });
                    if outcome == TraceOutcome::DestinationUnreachable {
                        break 'probe;
                    }
                    continue 'probe;
                }
                RouterAction::Drop { reason } => {
                    result.push(TraceHop {
                        ttl,
                        responder: None,
                        outcome: TraceOutcome::Dropped(reason),
                    });
                    continue 'probe;
                }
            }
        }

        // 所有 Router 都成功转发后，探测包才交给最终 Host。
        let reached = destination.receive_ip(&packet).is_some_and(|reply| {
            matches!(
                reply.payload,
                IpPayload::Icmp(crate::icmp::IcmpPacket {
                    message: IcmpMessage::EchoReply { .. }
                })
            )
        });
        if reached {
            result.push(TraceHop {
                ttl,
                responder: Some(destination_ip),
                outcome: TraceOutcome::ReachedDestination,
            });
            break;
        }

        result.push(TraceHop {
            ttl,
            responder: None,
            outcome: TraceOutcome::Timeout,
        });
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::MacAddr;
    use crate::routing::{Interface, RoutingTable};

    fn host(name: &str, ip: Ipv4Addr, mac_tail: u8) -> Host {
        Host::new(
            name,
            ip,
            Ipv4Addr { value: 0xFFFF_FF00 },
            RoutingTable::new(),
            MacAddr::new([0x02, 0, 0, 0, 0, mac_tail]),
        )
    }

    #[test]
    fn increasing_ttl_reveals_router_then_destination() {
        let mask = Ipv4Addr { value: 0xFFFF_FF00 };
        let alice_ip = Ipv4Addr { value: 0xC0A8_0102 };
        let bob_ip = Ipv4Addr { value: 0x0A00_0002 };
        let alice = host("Alice", alice_ip, 2);
        let bob = host("Bob", bob_ip, 3);

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
        let router = Router::new("R1", vec![left, right], routes);
        let path = [TraceRouter {
            router: &router,
            incoming_iface: 0,
        }];

        let hops = trace_route(&alice, &bob, bob_ip, &path, 4);
        assert_eq!(
            hops,
            vec![
                TraceHop {
                    ttl: 1,
                    responder: Some(Ipv4Addr { value: 0xC0A8_0101 }),
                    outcome: TraceOutcome::TimeExceeded,
                },
                TraceHop {
                    ttl: 2,
                    responder: Some(bob_ip),
                    outcome: TraceOutcome::ReachedDestination,
                },
            ]
        );
    }
}
