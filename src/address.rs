// ========== 二层:MAC 地址 ==========
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub fn new(bytes: [u8; 6]) -> Self {
        MacAddr(bytes)
    }
    // 广播地址 ff:ff:ff:ff:ff:ff
    pub fn broadcast() -> Self {
        MacAddr([0xFF; 6])
    }
    pub fn to_string(&self) -> String {
        self.0.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(":")
    }
}

// ========== 三层:IPv4 地址 ==========
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Addr {
    pub value: u32,
}

impl Ipv4Addr {
    // 转成点分十进制，例如 "192.168.10.37"
    pub fn to_dotted(&self) -> String {
        format!(
            "{}.{}.{}.{}",
            (self.value >> 24) & 0xFF,
            (self.value >> 16) & 0xFF,
            (self.value >> 8) & 0xFF,
            self.value & 0xFF
        )
    }
    // 子网掩码转前缀长度，例如 255.255.255.224 -> 27
    pub fn prefix_len(&self) -> u32 {
        self.value.leading_ones()
    }
}

// 计算网络地址
pub fn network_address(ip: Ipv4Addr, mask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr { value: ip.value & mask.value }
}

// 判断两个 IP 是否在同一子网
pub fn same_subnet(my_ip: Ipv4Addr, dst_ip: Ipv4Addr, mask: Ipv4Addr) -> bool {
    network_address(my_ip, mask).value == network_address(dst_ip, mask).value
}

// 前缀长度转子网掩码，例如 27 -> 255.255.255.224
pub fn prefix_to_mask(prefix: u8) -> Ipv4Addr {
    if prefix == 0 {
        return Ipv4Addr { value: 0 };
    }
    Ipv4Addr { value: u32::MAX << (32 - prefix as u32) }
}
