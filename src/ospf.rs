use std::collections::{HashMap, HashSet};

// ========== 简化版 OSPF(SPF 最短路径优先) ==========
//
// 真实 OSPF 是链路状态协议:每台路由器把「自己连了谁、代价多少」泛洪给全网,
// 大家拿到同一张拓扑图后,各自独立跑 Dijkstra(SPF)算出到每个目的地的最短路径。
// 这里只实现最核心的一步——拿到拓扑后做 SPF,演示「动态路由如何自动更新路由表」。

// 路由器 ID:这里直接复用名字(真实 OSPF 常用回环口 IP 当 Router-ID)
pub type RouterId = &'static str;

// 一条链路:无向,from/to 是对称的两端,cost 越小越优先
pub struct Link {
    pub from: RouterId,
    pub to: RouterId,
    pub cost: u32,
}

// SPF 算出来的一条路由条目(对应「目的路由器」的转发表项)
pub struct OspfRoute {
    pub dest: RouterId,     // 目的地
    pub cost: u32,          // 累计开销
    pub next_hop: RouterId, // 下一跳 = 从源出发要走的第一个邻居
}

// 网络拓扑:全网路由器 + 链路
pub struct Topology {
    routers: HashSet<RouterId>,
    links: Vec<Link>,
}

impl Topology {
    pub fn new(links: Vec<Link>) -> Self {
        let mut routers = HashSet::new();
        for l in &links {
            routers.insert(l.from);
            routers.insert(l.to);
        }
        Topology { routers, links }
    }

    // 链路 down(断开):从拓扑里移除,下次 SPF 就「看不见」它
    pub fn bring_link_down(&mut self, a: RouterId, b: RouterId) {
        self.links.retain(|l| !((l.from == a && l.to == b) || (l.from == b && l.to == a)));
    }

    // Dijkstra(SPF):从 source 出发,算到所有其他路由器的最短路径
    pub fn spf(&self, source: RouterId) -> Vec<OspfRoute> {
        // 1. 邻接表:路由器 -> [(邻居, 链路开销)]
        let mut adj: HashMap<RouterId, Vec<(RouterId, u32)>> =
            self.routers.iter().map(|&r| (r, Vec::new())).collect();
        for l in &self.links {
            adj.entry(l.from).or_default().push((l.to, l.cost));
            adj.entry(l.to).or_default().push((l.from, l.cost));
        }

        // 2. dist = 源到各路由器当前已知的最短距离;prev = 最短路径上的前驱
        let mut dist: HashMap<RouterId, u32> =
            self.routers.iter().map(|&r| (r, u32::MAX)).collect();
        let mut prev: HashMap<RouterId, RouterId> = HashMap::new();
        dist.insert(source, 0);

        // 3. unvisited = 还没「确定最短路径」的节点集合
        let mut unvisited: HashSet<RouterId> = self.routers.clone();

        // 4. 每轮挑 dist 最小的未确定节点,确定它,再拿它去「松弛」邻居
        while !unvisited.is_empty() {
            let current = unvisited
                .iter()
                .copied()
                .filter(|n| dist[n] != u32::MAX) // 只挑可达的,避免 MAX+1 溢出
                .min_by_key(|n| dist[n]);
            let current = match current {
                Some(c) => c,
                None => break, // 剩下的都不可达
            };
            unvisited.remove(&current);

            for &(neighbor, cost) in &adj[&current] {
                let new_dist = dist[&current] + cost;
                if new_dist < dist[&neighbor] {
                    dist.insert(neighbor, new_dist);
                    prev.insert(neighbor, current);
                }
            }
        }

        // 5. 汇总成路由表:对每个目的地,沿 prev 链回溯出「下一跳」
        let mut routes = Vec::new();
        for r in &self.routers {
            if *r == source {
                continue;
            }
            let d = dist[r];
            if d == u32::MAX {
                continue; // 不可达,不进路由表
            }
            routes.push(OspfRoute {
                dest: *r,
                cost: d,
                next_hop: first_hop(source, *r, &prev),
            });
        }
        routes.sort_by_key(|r| r.dest); // 稳定输出顺序
        routes
    }

    // 打印某台路由器的 SPF 结果(把它看作一张转发表)
    pub fn print_spf(&self, source: RouterId) {
        println!("[OSPF/SPF] Router {}", source);
        println!();
        println!("{:<11}   {:<4}   {}", "Destination", "Cost", "NextHop");
        for r in self.spf(source) {
            println!("{:<11}   {:<4}   {}", r.dest, r.cost, r.next_hop);
        }
    }
}

// 从 dest 沿 prev 链一路回溯到 source,最后一步的节点就是「下一跳」
fn first_hop(source: RouterId, dest: RouterId, prev: &HashMap<RouterId, RouterId>) -> RouterId {
    let mut hop = dest;
    while prev[&hop] != source {
        hop = prev[&hop];
    }
    hop
}
