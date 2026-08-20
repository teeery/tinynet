use std::collections::BTreeMap;

// ========== v0.5：简化 TCP 状态机 ==========
// 真实 TCP 还会处理同时打开、RST、拥塞控制等情况，v0.5 聚焦核心教学路径。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcpState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    LastAck,
    TimeWait,
}

// TCP 的 seq/ack 按“字节”编号；SYN 和 FIN 也各占用一个序号。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TcpSegment {
    pub seq: u32,
    pub ack: u32,
    pub syn: bool,
    pub ack_flag: bool,
    pub fin: bool,
    pub src_port: u16,
    pub dst_port: u16,
    pub window: u16,
    pub payload: Vec<u8>,
}

impl TcpSegment {
    pub fn flags(&self) -> String {
        let mut flags = Vec::new();
        if self.syn {
            flags.push("SYN");
        }
        if self.ack_flag {
            flags.push("ACK");
        }
        if self.fin {
            flags.push("FIN");
        }
        if flags.is_empty() {
            flags.push("DATA");
        }
        flags.join("+")
    }

    fn sequence_len(&self) -> u32 {
        self.payload.len() as u32 + u32::from(self.syn) + u32::from(self.fin)
    }
}

#[derive(Debug)]
pub struct TcpConnection {
    pub name: String,
    pub state: TcpState,
    pub local_port: u16,
    pub remote_port: u16,
    // 发送窗口左边界与下一个可用字节序号。
    pub send_base: u32,
    pub next_seq: u32,
    pub send_window: usize,
    pub unacked: BTreeMap<u32, TcpSegment>,
    // 接收缓冲区状态以及向对端通告的剩余窗口 rwnd。
    pub expected_seq: u32,
    pub recv_buffer_capacity: usize,
    pub recv_buffer_used: usize,
    pub rwnd: usize,
    recv_buffer: Vec<u8>,
    // 最近一次从对端报文中收到的通告窗口。
    pub peer_window: usize,
}

impl TcpConnection {
    pub fn client(
        name: &str,
        local_port: u16,
        remote_port: u16,
        initial_seq: u32,
        send_window: usize,
        recv_buffer_capacity: usize,
    ) -> Self {
        Self::new(
            name,
            TcpState::Closed,
            local_port,
            remote_port,
            initial_seq,
            send_window,
            recv_buffer_capacity,
        )
    }

    pub fn listener(
        name: &str,
        local_port: u16,
        initial_seq: u32,
        send_window: usize,
        recv_buffer_capacity: usize,
    ) -> Self {
        Self::new(
            name,
            TcpState::Listen,
            local_port,
            0,
            initial_seq,
            send_window,
            recv_buffer_capacity,
        )
    }

    fn new(
        name: &str,
        state: TcpState,
        local_port: u16,
        remote_port: u16,
        initial_seq: u32,
        send_window: usize,
        recv_buffer_capacity: usize,
    ) -> Self {
        assert!(send_window > 0, "TCP 发送窗口必须大于 0");
        assert!(recv_buffer_capacity > 0, "TCP 接收缓冲区必须大于 0");
        Self {
            name: name.to_string(),
            state,
            local_port,
            remote_port,
            send_base: initial_seq,
            next_seq: initial_seq,
            send_window,
            unacked: BTreeMap::new(),
            expected_seq: 0,
            recv_buffer_capacity,
            recv_buffer_used: 0,
            rwnd: recv_buffer_capacity,
            recv_buffer: Vec::new(),
            // 握手前还不知道对端窗口，先按本地发送窗口处理。
            peer_window: send_window,
        }
    }

    // ---------- 三次握手 ----------

    // 第一次握手：客户端发送 SYN，进入 SYN-SENT。
    pub fn connect(&mut self) -> Result<TcpSegment, String> {
        if self.state != TcpState::Closed {
            return Err(format!(
                "{} 当前状态 {:?} 不能主动连接",
                self.name, self.state
            ));
        }
        let syn = self.control_segment(true, false, false);
        self.track_sent(syn.clone());
        self.state = TcpState::SynSent;
        Ok(syn)
    }

    // 入站报文由当前状态决定如何处理，以及是否产生回复。
    pub fn receive(&mut self, segment: TcpSegment) -> Result<Option<TcpSegment>, String> {
        if segment.dst_port != self.local_port {
            return Err(format!(
                "{}: 目的端口 {} 与本地端口 {} 不匹配",
                self.name, segment.dst_port, self.local_port
            ));
        }
        match self.state {
            TcpState::Listen => self.receive_listen(segment),
            TcpState::SynSent => self.receive_syn_sent(segment),
            TcpState::SynReceived => self.receive_syn_received(segment),
            TcpState::Established => self.receive_established(segment),
            TcpState::FinWait1 => self.receive_fin_wait_1(segment),
            TcpState::FinWait2 => self.receive_fin_wait_2(segment),
            TcpState::CloseWait => self.receive_close_wait(segment),
            TcpState::LastAck => self.receive_last_ack(segment),
            TcpState::TimeWait => Ok(None),
            TcpState::Closed => Err(format!("{} 的连接已经关闭", self.name)),
        }
    }

    fn receive_listen(&mut self, segment: TcpSegment) -> Result<Option<TcpSegment>, String> {
        if !segment.syn || segment.ack_flag {
            return Err("LISTEN 状态只接受 SYN".to_string());
        }
        self.remote_port = segment.src_port;
        self.expected_seq = segment.seq + 1;
        self.peer_window = segment.window as usize;
        // 第二次握手：服务端确认客户端 SYN，同时发送自己的 SYN。
        let syn_ack = self.control_segment(true, true, false);
        self.track_sent(syn_ack.clone());
        self.state = TcpState::SynReceived;
        Ok(Some(syn_ack))
    }

    fn receive_syn_sent(&mut self, segment: TcpSegment) -> Result<Option<TcpSegment>, String> {
        if !(segment.syn && segment.ack_flag && segment.ack == self.next_seq) {
            return Err("SYN-SENT 期待合法的 SYN+ACK".to_string());
        }
        self.process_ack(segment.ack, segment.window);
        self.expected_seq = segment.seq + 1;
        // 第三次握手：客户端确认服务端 SYN；纯 ACK 不占用序号。
        self.state = TcpState::Established;
        Ok(Some(self.control_segment(false, true, false)))
    }

    fn receive_syn_received(&mut self, segment: TcpSegment) -> Result<Option<TcpSegment>, String> {
        if !(segment.ack_flag && !segment.syn && segment.ack == self.next_seq) {
            return Err("SYN-RECEIVED 期待第三次握手 ACK".to_string());
        }
        self.process_ack(segment.ack, segment.window);
        self.state = TcpState::Established;
        Ok(None)
    }

    // ---------- 滑动窗口与流量控制 ----------

    // 尽量发送 data，但不超过 min(本地发送窗口, 对端通告窗口)。返回结果可能
    // 只覆盖 data 的前一部分，剩余数据要等窗口更新后再次调用。
    pub fn send_data(&mut self, data: &[u8], mss: usize) -> Result<Vec<TcpSegment>, String> {
        if self.state != TcpState::Established {
            return Err(format!("{:?} 状态不能发送应用数据", self.state));
        }
        if mss == 0 {
            return Err("MSS 必须大于 0".to_string());
        }
        let in_flight = self.next_seq.saturating_sub(self.send_base) as usize;
        let mut available = self
            .send_window
            .min(self.peer_window)
            .saturating_sub(in_flight);
        let mut offset = 0;
        let mut segments = Vec::new();
        while offset < data.len() && available > 0 {
            let len = mss.min(available).min(data.len() - offset);
            let segment = TcpSegment {
                seq: self.next_seq,
                ack: self.expected_seq,
                syn: false,
                ack_flag: true,
                fin: false,
                src_port: self.local_port,
                dst_port: self.remote_port,
                window: self.advertised_window(),
                payload: data[offset..offset + len].to_vec(),
            };
            self.track_sent(segment.clone());
            segments.push(segment);
            offset += len;
            available -= len;
        }
        Ok(segments)
    }

    fn receive_established(&mut self, segment: TcpSegment) -> Result<Option<TcpSegment>, String> {
        if segment.ack_flag {
            self.process_ack(segment.ack, segment.window);
        }
        if segment.fin {
            if segment.seq != self.expected_seq {
                return Err(format!(
                    "期待 FIN seq={}，收到 {}",
                    self.expected_seq, segment.seq
                ));
            }
            self.expected_seq += 1; // FIN 占一个序号。
            self.state = TcpState::CloseWait;
            return Ok(Some(self.control_segment(false, true, false)));
        }
        if segment.payload.is_empty() {
            return Ok(None);
        } // 纯 ACK/窗口更新。
        if segment.seq != self.expected_seq {
            // v0.5 不缓存乱序数据，重复 ACK 当前期待序号。
            return Ok(Some(self.control_segment(false, true, false)));
        }
        if segment.payload.len() > self.rwnd {
            return Err("对端发送的数据超过了本端通告窗口".to_string());
        }
        self.expected_seq += segment.payload.len() as u32;
        self.recv_buffer.extend_from_slice(&segment.payload);
        self.refresh_receive_window();
        Ok(Some(self.control_segment(false, true, false)))
    }

    // 应用层取走数据后，接收窗口重新变大。
    pub fn application_read(&mut self, max_bytes: usize) -> Vec<u8> {
        let count = max_bytes.min(self.recv_buffer.len());
        let data = self.recv_buffer.drain(..count).collect();
        self.refresh_receive_window();
        data
    }

    // 纯 ACK 把更新后的 rwnd 通告给发送方。
    pub fn window_update(&self) -> Result<TcpSegment, String> {
        if !matches!(self.state, TcpState::Established | TcpState::CloseWait) {
            return Err("当前状态不能发送窗口更新".to_string());
        }
        Ok(self.control_segment(false, true, false))
    }

    // ---------- 四次挥手 ----------

    pub fn close(&mut self) -> Result<TcpSegment, String> {
        let next_state = match self.state {
            TcpState::Established => TcpState::FinWait1,
            TcpState::CloseWait => TcpState::LastAck,
            _ => return Err(format!("{:?} 状态不能执行 close", self.state)),
        };
        let fin = self.control_segment(false, true, true);
        self.track_sent(fin.clone());
        self.state = next_state;
        Ok(fin)
    }

    fn receive_fin_wait_1(&mut self, segment: TcpSegment) -> Result<Option<TcpSegment>, String> {
        if segment.ack_flag && segment.ack == self.next_seq {
            self.process_ack(segment.ack, segment.window);
            self.state = TcpState::FinWait2;
            Ok(None)
        } else {
            Err("FIN-WAIT-1 期待对 FIN 的 ACK".to_string())
        }
    }

    fn receive_fin_wait_2(&mut self, segment: TcpSegment) -> Result<Option<TcpSegment>, String> {
        if !segment.fin || segment.seq != self.expected_seq {
            return Err("FIN-WAIT-2 期待对端 FIN".to_string());
        }
        if segment.ack_flag {
            self.process_ack(segment.ack, segment.window);
        }
        self.expected_seq += 1;
        self.state = TcpState::TimeWait;
        Ok(Some(self.control_segment(false, true, false)))
    }

    fn receive_close_wait(&mut self, segment: TcpSegment) -> Result<Option<TcpSegment>, String> {
        if segment.ack_flag {
            self.process_ack(segment.ack, segment.window);
            Ok(None)
        } else {
            Err("CLOSE-WAIT 只接受 ACK；应用层应调用 close".to_string())
        }
    }

    fn receive_last_ack(&mut self, segment: TcpSegment) -> Result<Option<TcpSegment>, String> {
        if segment.ack_flag && segment.ack == self.next_seq {
            self.process_ack(segment.ack, segment.window);
            self.state = TcpState::Closed;
            Ok(None)
        } else {
            Err("LAST-ACK 期待最后一个 ACK".to_string())
        }
    }

    // 一次显式调用代表 TIME-WAIT 的 2MSL 已到期。
    pub fn expire_time_wait(&mut self) -> Result<(), String> {
        if self.state != TcpState::TimeWait {
            return Err("只有 TIME-WAIT 状态可以等待 2MSL 到期".to_string());
        }
        self.state = TcpState::Closed;
        Ok(())
    }

    fn control_segment(&self, syn: bool, ack_flag: bool, fin: bool) -> TcpSegment {
        TcpSegment {
            seq: self.next_seq,
            ack: if ack_flag { self.expected_seq } else { 0 },
            syn,
            ack_flag,
            fin,
            src_port: self.local_port,
            dst_port: self.remote_port,
            window: self.advertised_window(),
            payload: Vec::new(),
        }
    }

    fn track_sent(&mut self, segment: TcpSegment) {
        let sequence_len = segment.sequence_len();
        if sequence_len > 0 {
            self.unacked.insert(segment.seq, segment);
            self.next_seq += sequence_len;
        }
    }

    fn process_ack(&mut self, ack: u32, advertised_window: u16) {
        self.peer_window = advertised_window as usize;
        if ack <= self.send_base || ack > self.next_seq {
            return;
        }
        self.unacked
            .retain(|seq, segment| *seq + segment.sequence_len() > ack);
        self.send_base = ack;
    }

    fn refresh_receive_window(&mut self) {
        self.recv_buffer_used = self.recv_buffer.len();
        self.rwnd = self
            .recv_buffer_capacity
            .saturating_sub(self.recv_buffer_used);
    }

    fn advertised_window(&self) -> u16 {
        self.rwnd.min(u16::MAX as usize) as u16
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn established_pair(server_capacity: usize) -> (TcpConnection, TcpConnection) {
        let mut client = TcpConnection::client("client", 50_000, 80, 1000, 16, 16);
        let mut server = TcpConnection::listener("server", 80, 5000, 16, server_capacity);
        let syn = client.connect().unwrap();
        let syn_ack = server.receive(syn).unwrap().unwrap();
        let ack = client.receive(syn_ack).unwrap().unwrap();
        server.receive(ack).unwrap();
        (client, server)
    }

    #[test]
    fn three_way_handshake_establishes_both_ends() {
        let (client, server) = established_pair(8);
        assert_eq!(client.state, TcpState::Established);
        assert_eq!(server.state, TcpState::Established);
        assert_eq!(client.send_base, 1001); // SYN 消耗一个序号。
        assert_eq!(server.send_base, 5001);
    }

    #[test]
    fn advertised_window_limits_sender_and_slides_after_ack() {
        let (mut client, mut server) = established_pair(8);
        let data = b"abcdefghijkl";
        let first = client.send_data(data, 4).unwrap();
        assert_eq!(first.iter().map(|s| s.payload.len()).sum::<usize>(), 8);
        for segment in first {
            let ack = server.receive(segment).unwrap().unwrap();
            client.receive(ack).unwrap();
        }
        assert_eq!(server.rwnd, 0);
        assert!(client.send_data(&data[8..], 4).unwrap().is_empty());
        assert_eq!(server.application_read(4), b"abcd");
        client.receive(server.window_update().unwrap()).unwrap();
        assert_eq!(client.send_data(&data[8..], 4).unwrap().len(), 1);
    }

    #[test]
    fn four_way_close_reaches_closed_after_time_wait() {
        let (mut client, mut server) = established_pair(8);
        let fin1 = client.close().unwrap();
        let ack1 = server.receive(fin1).unwrap().unwrap();
        client.receive(ack1).unwrap();
        assert_eq!(client.state, TcpState::FinWait2);
        assert_eq!(server.state, TcpState::CloseWait);
        let fin2 = server.close().unwrap();
        let ack2 = client.receive(fin2).unwrap().unwrap();
        server.receive(ack2).unwrap();
        assert_eq!(client.state, TcpState::TimeWait);
        assert_eq!(server.state, TcpState::Closed);
        client.expire_time_wait().unwrap();
        assert_eq!(client.state, TcpState::Closed);
    }
}
