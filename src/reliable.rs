use std::collections::{BTreeMap, HashSet};

// ========== v0.4：可靠传输层的基本数据单元 ==========
//
// seq 用来给数据排序；接收方返回 ACK 后，发送方才知道该数据已经安全到达。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub seq: u32,
    pub data: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Timer {
    elapsed: u32,
    timeout: u32,
}

impl Timer {
    fn new(timeout: u32) -> Self {
        Self {
            elapsed: 0,
            timeout,
        }
    }

    // 返回 true 表示本次 tick 触发超时。
    fn tick(&mut self) -> bool {
        self.elapsed += 1;
        if self.elapsed >= self.timeout {
            self.elapsed = 0;
            true
        } else {
            false
        }
    }
}

// ========== GBN 发送端 ==========
//
// GBN 只为窗口中最早的未确认报文维护一个计时器。一旦它超时，窗口内所有
// 未确认报文都要重传，这正是 Go-Back-N（回退 N 帧）名字的来源。
#[derive(Debug)]
pub struct GbnSender {
    pub send_base: u32,
    pub next_seq: u32,
    pub window_size: u32,
    pub unacked_queue: BTreeMap<u32, Segment>,
    pub timer: Option<Timer>,
    timeout: u32,
}

impl GbnSender {
    pub fn new(window_size: u32, timeout: u32) -> Self {
        assert!(window_size > 0, "GBN 窗口必须大于 0");
        assert!(timeout > 0, "超时时间必须大于 0");
        Self {
            send_base: 1,
            next_seq: 1,
            window_size,
            unacked_queue: BTreeMap::new(),
            timer: None,
            timeout,
        }
    }

    pub fn send(&mut self, data: impl Into<String>) -> Option<Segment> {
        if self.next_seq >= self.send_base + self.window_size {
            return None; // 发送窗口已满，必须先等待 ACK。
        }

        let segment = Segment {
            seq: self.next_seq,
            data: data.into(),
        };
        self.next_seq += 1;
        self.unacked_queue.insert(segment.seq, segment.clone());
        if self.timer.is_none() {
            self.timer = Some(Timer::new(self.timeout));
        }
        Some(segment)
    }

    // GBN 使用累计确认：ACK=n 表示 1..=n 已经连续到达。
    pub fn receive_ack(&mut self, ack: u32) {
        if ack < self.send_base || ack >= self.next_seq {
            return; // 重复 ACK 或无效 ACK 不推进窗口。
        }

        self.unacked_queue.retain(|seq, _| *seq > ack);
        self.send_base = self
            .unacked_queue
            .first_key_value()
            .map(|(seq, _)| *seq)
            .unwrap_or(self.next_seq);

        self.timer = if self.unacked_queue.is_empty() {
            None
        } else {
            Some(Timer::new(self.timeout))
        };
    }

    // 每调用一次表示时间前进一步；超时时返回“全部未确认报文”。
    pub fn tick(&mut self) -> Vec<Segment> {
        let timed_out = self.timer.as_mut().is_some_and(Timer::tick);
        if !timed_out {
            return Vec::new();
        }
        self.unacked_queue.values().cloned().collect()
    }
}

// ========== GBN 接收端 ==========
#[derive(Debug)]
pub struct GbnReceiver {
    pub expected_seq: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub struct ReceiveResult {
    pub ack: Option<u32>,
    pub delivered: Vec<Segment>,
    pub buffered: bool,
}

impl GbnReceiver {
    pub fn new() -> Self {
        Self { expected_seq: 1 }
    }

    pub fn receive(&mut self, segment: Segment) -> ReceiveResult {
        if segment.seq == self.expected_seq {
            let ack = segment.seq;
            self.expected_seq += 1;
            ReceiveResult {
                ack: Some(ack),
                delivered: vec![segment],
                buffered: false,
            }
        } else {
            // GBN 不缓存乱序报文，只重复确认最后一个连续收到的序号。
            ReceiveResult {
                ack: Some(self.expected_seq.saturating_sub(1)),
                delivered: Vec::new(),
                buffered: false,
            }
        }
    }
}

// ========== SR 发送端 ==========
//
// SR 为每个未确认报文分别计时，因此哪个报文超时就只重传哪个报文。
#[derive(Debug)]
pub struct SrSender {
    pub send_base: u32,
    pub next_seq: u32,
    pub window_size: u32,
    pub unacked_queue: BTreeMap<u32, Segment>,
    pub timers: BTreeMap<u32, Timer>,
    timeout: u32,
}

impl SrSender {
    pub fn new(window_size: u32, timeout: u32) -> Self {
        assert!(window_size > 0, "SR 窗口必须大于 0");
        assert!(timeout > 0, "超时时间必须大于 0");
        Self {
            send_base: 1,
            next_seq: 1,
            window_size,
            unacked_queue: BTreeMap::new(),
            timers: BTreeMap::new(),
            timeout,
        }
    }

    pub fn send(&mut self, data: impl Into<String>) -> Option<Segment> {
        if self.next_seq >= self.send_base + self.window_size {
            return None;
        }
        let segment = Segment {
            seq: self.next_seq,
            data: data.into(),
        };
        self.next_seq += 1;
        self.unacked_queue.insert(segment.seq, segment.clone());
        self.timers.insert(segment.seq, Timer::new(self.timeout));
        Some(segment)
    }

    // SR 的 ACK 只确认一个指定序号，不代表更早的报文一定到达。
    pub fn receive_ack(&mut self, ack: u32) {
        self.unacked_queue.remove(&ack);
        self.timers.remove(&ack);

        // 窗口基线只能越过已经确认的连续区间；例如 ACK 3 不能跳过丢失的 2。
        while self.send_base < self.next_seq && !self.unacked_queue.contains_key(&self.send_base) {
            self.send_base += 1;
        }
    }

    pub fn tick(&mut self) -> Vec<Segment> {
        let timed_out: Vec<u32> = self
            .timers
            .iter_mut()
            .filter_map(|(seq, timer)| timer.tick().then_some(*seq))
            .collect();

        timed_out
            .into_iter()
            .filter_map(|seq| self.unacked_queue.get(&seq).cloned())
            .collect()
    }
}

// ========== SR 接收端 ==========
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiveWindow {
    pub base: u32,
    pub size: u32,
}

#[derive(Debug)]
pub struct SrReceiver {
    pub receive_window: ReceiveWindow,
    pub buffer: BTreeMap<u32, Segment>,
}

impl SrReceiver {
    pub fn new(window_size: u32) -> Self {
        assert!(window_size > 0, "SR 接收窗口必须大于 0");
        Self {
            receive_window: ReceiveWindow {
                base: 1,
                size: window_size,
            },
            buffer: BTreeMap::new(),
        }
    }

    pub fn receive(&mut self, segment: Segment) -> ReceiveResult {
        let seq = segment.seq;
        let lower = self.receive_window.base;
        let upper = lower + self.receive_window.size;

        if seq < lower {
            // 已交付报文的重传副本：再次 ACK，帮助发送方结束重传。
            return ReceiveResult {
                ack: Some(seq),
                delivered: Vec::new(),
                buffered: false,
            };
        }
        if seq >= upper {
            return ReceiveResult {
                ack: None,
                delivered: Vec::new(),
                buffered: false,
            };
        }

        let buffered = seq != lower;
        self.buffer.entry(seq).or_insert(segment);

        // 从窗口左边界开始，把现在已经连续的数据一次性交付给应用层。
        let mut delivered = Vec::new();
        while let Some(segment) = self.buffer.remove(&self.receive_window.base) {
            delivered.push(segment);
            self.receive_window.base += 1;
        }
        ReceiveResult {
            ack: Some(seq),
            delivered,
            buffered,
        }
    }
}

// ========== 会丢包的教学网络 ==========
#[derive(Debug)]
pub enum LossMode {
    // 精确丢弃指定序号的第一次发送，适合稳定复现实验。
    DropOnce {
        seqs: HashSet<u32>,
        dropped: HashSet<u32>,
    },
    // 可复现的伪随机丢包；相同 seed 会得到相同实验结果。
    Random {
        loss_percent: u8,
        state: u64,
    },
}

#[derive(Debug)]
pub struct LossyNetwork {
    mode: LossMode,
}

impl LossyNetwork {
    pub fn drop_once(seqs: impl IntoIterator<Item = u32>) -> Self {
        Self {
            mode: LossMode::DropOnce {
                seqs: seqs.into_iter().collect(),
                dropped: HashSet::new(),
            },
        }
    }

    pub fn random(loss_percent: u8, seed: u64) -> Self {
        assert!(loss_percent <= 100, "丢包率必须在 0..=100 之间");
        Self {
            mode: LossMode::Random {
                loss_percent,
                state: seed,
            },
        }
    }

    // Some 表示成功送达，None 表示在链路中丢失。
    pub fn transmit(&mut self, segment: Segment) -> Option<Segment> {
        let should_drop = match &mut self.mode {
            LossMode::DropOnce { seqs, dropped } => {
                seqs.contains(&segment.seq) && dropped.insert(segment.seq)
            }
            LossMode::Random {
                loss_percent,
                state,
            } => {
                // 简单 LCG 足够用于教学模拟，不用于密码学或真实网络随机数。
                *state = state
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1);
                ((*state >> 32) % 100) < u64::from(*loss_percent)
            }
        };
        (!should_drop).then_some(segment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gbn_discards_out_of_order_and_retransmits_whole_unacked_window() {
        let mut sender = GbnSender::new(4, 2);
        let mut receiver = GbnReceiver::new();
        let mut network = LossyNetwork::drop_once([2]);

        for seq in 1..=4 {
            let segment = sender.send(format!("data-{seq}")).unwrap();
            if let Some(segment) = network.transmit(segment) {
                let result = receiver.receive(segment);
                sender.receive_ack(result.ack.unwrap());
            }
        }

        assert_eq!(receiver.expected_seq, 2);
        assert!(sender.tick().is_empty());
        let retransmitted = sender.tick();
        assert_eq!(
            retransmitted.iter().map(|s| s.seq).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }

    #[test]
    fn sr_buffers_out_of_order_and_retransmits_only_missing_segment() {
        let mut sender = SrSender::new(4, 2);
        let mut receiver = SrReceiver::new(4);
        let mut network = LossyNetwork::drop_once([2]);

        for seq in 1..=4 {
            let segment = sender.send(format!("data-{seq}")).unwrap();
            if let Some(segment) = network.transmit(segment) {
                let result = receiver.receive(segment);
                sender.receive_ack(result.ack.unwrap());
            }
        }

        assert_eq!(
            receiver.buffer.keys().copied().collect::<Vec<_>>(),
            vec![3, 4]
        );
        assert!(sender.tick().is_empty());
        let retransmitted = sender.tick();
        assert_eq!(
            retransmitted.iter().map(|s| s.seq).collect::<Vec<_>>(),
            vec![2]
        );

        let result = receiver.receive(retransmitted[0].clone());
        assert_eq!(
            result.delivered.iter().map(|s| s.seq).collect::<Vec<_>>(),
            vec![2, 3, 4]
        );
    }

    #[test]
    fn sender_window_blocks_new_data_until_base_moves() {
        let mut sender = GbnSender::new(2, 3);
        assert!(sender.send("one").is_some());
        assert!(sender.send("two").is_some());
        assert!(sender.send("blocked").is_none());
        sender.receive_ack(1);
        assert_eq!(sender.send_base, 2);
        assert!(sender.send("three").is_some());
    }

    #[test]
    fn random_network_honors_loss_rate_boundaries() {
        let segment = Segment {
            seq: 1,
            data: "data".to_string(),
        };
        assert!(LossyNetwork::random(0, 7)
            .transmit(segment.clone())
            .is_some());
        assert!(LossyNetwork::random(100, 7).transmit(segment).is_none());
    }
}
