use crate::address::Ipv4Addr;

// ========== v0.6：ICMP 报文 ==========
//
// ICMP 只描述“消息是什么”，不负责查路由、ARP 或构造以太网帧。
// IpPacket 会在外层提供 src、dst 和 ttl。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IcmpPacket {
    pub message: IcmpMessage,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IcmpMessage {
    EchoRequest {
        identifier: u16,
        sequence: u16,
        data: Vec<u8>,
    },
    EchoReply {
        identifier: u16,
        sequence: u16,
        data: Vec<u8>,
    },
    TimeExceeded {
        original_src: Ipv4Addr,
        original_dst: Ipv4Addr,
    },
    DestinationUnreachable {
        original_src: Ipv4Addr,
        original_dst: Ipv4Addr,
    },
}

impl IcmpPacket {
    pub fn echo_request(identifier: u16, sequence: u16, data: Vec<u8>) -> Self {
        Self {
            message: IcmpMessage::EchoRequest {
                identifier,
                sequence,
                data,
            },
        }
    }

    pub fn echo_reply(identifier: u16, sequence: u16, data: Vec<u8>) -> Self {
        Self {
            message: IcmpMessage::EchoReply {
                identifier,
                sequence,
                data,
            },
        }
    }

    pub fn time_exceeded(original_src: Ipv4Addr, original_dst: Ipv4Addr) -> Self {
        Self {
            message: IcmpMessage::TimeExceeded {
                original_src,
                original_dst,
            },
        }
    }

    pub fn destination_unreachable(original_src: Ipv4Addr, original_dst: Ipv4Addr) -> Self {
        Self {
            message: IcmpMessage::DestinationUnreachable {
                original_src,
                original_dst,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_request_keeps_identifier_sequence_and_data() {
        let packet = IcmpPacket::echo_request(7, 3, b"tinynet".to_vec());
        assert_eq!(
            packet.message,
            IcmpMessage::EchoRequest {
                identifier: 7,
                sequence: 3,
                data: b"tinynet".to_vec(),
            }
        );
    }
}
