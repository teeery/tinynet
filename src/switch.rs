use std::collections::HashMap;
use std::rc::Rc;

use crate::address::MacAddr;
use crate::host::{Host, HostAction};
use crate::packet::EthernetFrame;

// ========== 交换机 ==========
pub struct Switch {
    ports: HashMap<usize, Rc<Host>>,    // 端口号 -> 主机
    mac_table: HashMap<MacAddr, usize>, // MAC 地址表:MAC -> 端口号
}

impl Switch {
    pub fn new() -> Self {
        Switch {
            ports: HashMap::new(),
            mac_table: HashMap::new(),
        }
    }

    pub fn connect(&mut self, port: usize, host: Rc<Host>) {
        self.ports.insert(port, host);
    }

    // 找到帧的来源端口(现实中硬件直接知道入端口;这里通过 MAC 反查模拟)
    fn source_port(&self, mac: MacAddr) -> Option<usize> {
        self.ports
            .iter()
            .find(|(_, h)| h.mac == mac)
            .map(|(p, _)| *p)
    }

    // 转发一帧:MAC Learning + 查表 + 单播/广播
    pub fn forward(&mut self, frame: EthernetFrame) {
        let src_port = self.source_port(frame.src);

        // 1. MAC Learning:记下「源 MAC -> 来源端口」
        if let Some(port) = src_port {
            if self.mac_table.insert(frame.src, port).is_none() {
                println!("[交换机] 学习 {} -> 端口{}", frame.src.to_string(), port);
            }
        }

        // 2. 查表确定目标端口
        let targets: Vec<usize> = match self.mac_table.get(&frame.dst) {
            Some(&port) => {
                println!(
                    "[交换机] 查表命中 {} -> 端口{}",
                    frame.dst.to_string(),
                    port
                );
                vec![port]
            }
            None => {
                println!("[交换机] 查表未命中,广播到所有其他端口");
                self.ports
                    .keys()
                    .copied()
                    .filter(|&p| Some(p) != src_port)
                    .collect()
            }
        };

        // 3. 投递
        for port in targets {
            let host = self.ports.get(&port).cloned();
            if let Some(host) = host {
                if let Some(action) = host.receive(&frame) {
                    match action {
                        // ARP Reply 已经是完整的二层帧，可以直接转发。
                        HostAction::SendEthernet(reply) => self.forward(reply),
                        // ICMP Reply 是新的 IP 包，必须重新查路由、ARP 和封装 Ethernet。
                        HostAction::SendIp(reply) => {
                            if let Err(error) = host.send_ip(reply, self) {
                                println!("[交换机] {} 回复失败: {}", host.mac.to_string(), error);
                            }
                        }
                    }
                }
            }
        }
    }
}
