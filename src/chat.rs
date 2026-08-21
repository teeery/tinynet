use crate::address::Ipv4Addr;
use crate::internet::{InternetError, MiniInternet};
use crate::network::NodeId;

// ========== v1.0：最小聊天应用协议 ==========
// TCP 负责可靠、有序的字节流；Chat 只定义这些字节在应用层代表什么。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChatMessage {
    pub id: u32,
    pub from: String,
    pub text: String,
}

impl ChatMessage {
    // 教学用线格式：id\nfrom\ntext。实际系统会使用 JSON/Protobuf 等编码。
    pub fn to_bytes(&self) -> Vec<u8> {
        format!("{}\n{}\n{}", self.id, self.from, self.text).into_bytes()
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "Chat 消息不是 UTF-8")?;
        let mut fields = text.splitn(3, '\n');
        let id = fields
            .next()
            .ok_or("Chat 消息缺少 id")?
            .parse()
            .map_err(|_| "Chat 消息 id 非法")?;
        let from = fields.next().ok_or("Chat 消息缺少发送者")?.to_string();
        let text = fields.next().ok_or("Chat 消息缺少正文")?.to_string();
        Ok(Self { id, from, text })
    }
}

pub struct ChatApp {
    pub name: String,
    pub node: NodeId,
    pub local_port: u16,
    next_message_id: u32,
}

impl ChatApp {
    pub fn new(name: &str, node: NodeId, local_port: u16) -> Self {
        Self {
            name: name.to_string(),
            node,
            local_port,
            next_message_id: 1,
        }
    }

    pub fn listen(&self, internet: &mut MiniInternet) -> Result<(), InternetError> {
        internet.bind_tcp_listener(self.node, self.local_port)
    }

    pub fn connect(
        &self,
        internet: &mut MiniInternet,
        peer_ip: Ipv4Addr,
        peer_port: u16,
    ) -> Result<(), InternetError> {
        internet.tcp_connect(self.node, self.local_port, peer_ip, peer_port)
    }

    pub fn send(&mut self, internet: &mut MiniInternet, text: &str) -> Result<u32, InternetError> {
        let id = self.next_message_id;
        self.next_message_id += 1;
        let message = ChatMessage {
            id,
            from: self.name.clone(),
            text: text.to_string(),
        };
        internet.send_tcp_bytes(self.node, self.local_port, &message.to_bytes())?;
        Ok(id)
    }

    pub fn receive(
        &self,
        internet: &mut MiniInternet,
    ) -> Result<Option<ChatMessage>, InternetError> {
        let bytes = internet.read_tcp_bytes(self.node, self.local_port)?;
        if bytes.is_empty() {
            Ok(None)
        } else {
            ChatMessage::parse(&bytes)
                .map(Some)
                .map_err(InternetError::Tcp)
        }
    }

    pub fn close(&self, internet: &mut MiniInternet) -> Result<(), InternetError> {
        internet.tcp_close(self.node, self.local_port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_message_round_trip_keeps_unicode_text() {
        let message = ChatMessage {
            id: 7,
            from: "小明".to_string(),
            text: "小红，你好！".to_string(),
        };
        assert_eq!(ChatMessage::parse(&message.to_bytes()).unwrap(), message);
    }
}
