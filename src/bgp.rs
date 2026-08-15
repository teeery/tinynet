use std::cmp::Ordering;
use std::collections::HashMap;

use crate::address::Ipv4Addr;

// ========== v0.7:简化版 BGP(路径向量 + 策略选路) ==========
//
// 真实 BGP 是「路径向量」协议:每条路由不是一个数字(距离/开销),
// 而是一串 AS 编号 —— AS_PATH,记录「这条路依次经过哪些自治系统」。
// 选路时不看链路开销(那是 OSPF/Dijkstra 的事),而是:
//   1. 先看策略(local_pref,本地优先级):我偏好谁,谁的路就更优先
//   2. 再看 AS_PATH 长度:越短越优先
//   3. 最后兜底(教学简化):AS_PATH 字典序,保证结果确定
//
// 这就是 IGP 和 EGP 的根本区别:
//   OSPF(IGP):AS 内部,大家共享拓扑 → Dijkstra 比开销
//   BGP(EGP) :AS 之间,管不着别人内部 → 只看策略 + 路径

// 自治系统号(ASN):给每个「独立管理的网络」编的号
pub type Asn = u32;

// 目的前缀:一个 IP 网络,如 20.0.0.0/8
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prefix {
    pub network: Ipv4Addr,
    pub prefix_len: u8,
}

impl Prefix {
    pub fn new(network: Ipv4Addr, prefix_len: u8) -> Self {
        Prefix { network, prefix_len }
    }

    // 显示成 "20.0.0.0/8"
    pub fn to_string(&self) -> String {
        format!("{}/{}", self.network.to_dotted(), self.prefix_len)
    }
}

// BGP 默认本地优先级:所有路由平起平坐时的基准值
pub const DEFAULT_LOCAL_PREF: u32 = 100;

// 一条 BGP 路由:目的前缀 + AS 路径 + 本地优先级(策略值)
pub struct BgpRoute {
    pub prefix: Prefix,    // 这条路由通向的目的网络
    pub as_path: Vec<Asn>, // 路径,从右往左读:最右边是始发 AS,最左边是「告诉我的邻居」
    pub local_pref: u32,   // 本地优先级:越大越优先,默认 100,策略可以改
}

impl BgpRoute {
    // 新建一条路由,local_pref 用默认值 100
    pub fn new(prefix: Prefix, as_path: Vec<Asn>) -> Self {
        BgpRoute { prefix, as_path, local_pref: DEFAULT_LOCAL_PREF }
    }

    // 这条路由是从哪个邻居 AS 学到的(= AS_PATH 最左边那个)
    pub fn neighbor(&self) -> Asn {
        self.as_path[0]
    }

    // 显示成 "20.0.0.0/8  [AS2, AS3]  local_pref=100"
    pub fn to_string(&self) -> String {
        let path = self
            .as_path
            .iter()
            .map(|a| format!("AS{}", a))
            .collect::<Vec<_>>()
            .join(", ");
        format!("{}  [{}]  local_pref={}", self.prefix.to_string(), path, self.local_pref)
    }
}

// ========== BGP 选路决策(简化版) ==========
// 依次比较,第一个分出高下的规则生效:
//   1. local_pref(策略):越大越优先
//   2. AS_PATH 长度:越短越优先
//   3. 兜底:AS_PATH 字典序(真实 BGP 后面还有 MED、eBGP/iBGP、Router-ID 等,这里省略)
//
// 前提:routes 非空
pub fn select_bgp_route(routes: &[BgpRoute]) -> &BgpRoute {
    routes
        .iter()
        .max_by(|a, b| cmp_route(a, b))
        .expect("select_bgp_route: routes 不能为空")
}

// 比较两条路由谁更优:返回 Greater 表示 a 更优
fn cmp_route(a: &BgpRoute, b: &BgpRoute) -> Ordering {
    a.local_pref
        .cmp(&b.local_pref)                                  // 1. 策略:local_pref 越大越优
        .then_with(|| b.as_path.len().cmp(&a.as_path.len())) // 2. AS_PATH 越短越优
        .then_with(|| b.as_path.cmp(&a.as_path))             // 3. 兜底:AS_PATH 字典序越小越优
}

// ========== BGP 策略:一个 AS 的「偏好」 ==========
// 真实配置里长这样:
//   neighbor 4.4.4.4 route-map PREFER-AS4 in
//   route-map PREFER-AS4 permit 10
//     set local-preference 200
// 这里简化成一张表:邻居 ASN -> 给它学到的路由设的 local_pref
pub struct BgpPolicy {
    pub asn: Asn, // 这是哪个 AS 的策略
    neighbor_pref: HashMap<Asn, u32>,
}

impl BgpPolicy {
    pub fn new(asn: Asn) -> Self {
        BgpPolicy { asn, neighbor_pref: HashMap::new() }
    }

    // 配置策略:我偏好邻居 X,它告诉我的路由 local_pref 提高到 pref
    pub fn prefer(&mut self, neighbor: Asn, pref: u32) -> &mut Self {
        self.neighbor_pref.insert(neighbor, pref);
        self
    }

    // 应用策略:按「这条路由来自哪个邻居」调整 local_pref(没配的保持默认 100)
    pub fn apply(&self, route: &mut BgpRoute) {
        if let Some(pref) = self.neighbor_pref.get(&route.neighbor()) {
            route.local_pref = *pref;
        }
    }
}
