use std::collections::HashMap;

use crate::address::Ipv4Addr;
use crate::packet::{IpPacket, IpPayload};
use crate::udp::{UdpDatagram, UdpPayload};

pub const DNS_PORT: u16 = 53;

// ========== DNS 消息与资源记录 ==========
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    Cname,
    Ns,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub record_type: DnsRecordType,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub ttl: u32,
    pub data: DnsRecordData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsRecordData {
    A(Ipv4Addr),
    Cname(String),
    Ns(String),
}

impl DnsRecord {
    pub fn a(name: &str, ip: Ipv4Addr, ttl: u32) -> Self {
        Self {
            name: normalize_name(name),
            ttl,
            data: DnsRecordData::A(ip),
        }
    }

    pub fn cname(name: &str, canonical_name: &str, ttl: u32) -> Self {
        Self {
            name: normalize_name(name),
            ttl,
            data: DnsRecordData::Cname(normalize_name(canonical_name)),
        }
    }

    pub fn ns(zone: &str, name_server: &str, ttl: u32) -> Self {
        Self {
            name: normalize_name(zone),
            ttl,
            data: DnsRecordData::Ns(normalize_name(name_server)),
        }
    }

    fn record_type(&self) -> DnsRecordType {
        match self.data {
            DnsRecordData::A(_) => DnsRecordType::A,
            DnsRecordData::Cname(_) => DnsRecordType::Cname,
            DnsRecordData::Ns(_) => DnsRecordType::Ns,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub is_response: bool,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}

impl DnsMessage {
    pub fn query(id: u16, name: &str, record_type: DnsRecordType) -> Self {
        Self {
            id,
            is_response: false,
            questions: vec![DnsQuestion {
                name: normalize_name(name),
                record_type,
            }],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
}

// ========== Root / TLD / Authoritative Server ==========
#[derive(Debug)]
pub struct DnsServer {
    pub name: String,
    pub ip: Ipv4Addr,
    pub records: Vec<DnsRecord>,
}

impl DnsServer {
    pub fn new(name: &str, ip: Ipv4Addr, records: Vec<DnsRecord>) -> Self {
        Self {
            name: name.to_string(),
            ip,
            records,
        }
    }

    // DNS Server 接收的是 UDP 数据报，并从 53 端口返回响应。
    pub fn handle_udp(&self, datagram: &UdpDatagram) -> Result<UdpDatagram, DnsResolveError> {
        if datagram.dst_port != DNS_PORT {
            return Err(DnsResolveError::WrongDestinationPort(datagram.dst_port));
        }
        let UdpPayload::Dns(query) = &datagram.payload;
        let question = query
            .questions
            .first()
            .ok_or(DnsResolveError::MissingQuestion)?;

        let answers: Vec<DnsRecord> = self
            .records
            .iter()
            .filter(|record| {
                record.name == question.name && record.record_type() == question.record_type
            })
            .cloned()
            .collect();

        // 没有最终答案时，选择能匹配查询名的最长 NS 区域作为 referral。
        let authorities = if answers.is_empty() {
            let best_zone_length = self
                .records
                .iter()
                .filter(|record| {
                    matches!(record.data, DnsRecordData::Ns(_))
                        && name_belongs_to_zone(&question.name, &record.name)
                })
                .map(|record| record.name.len())
                .max();
            self.records
                .iter()
                .filter(|record| {
                    matches!(record.data, DnsRecordData::Ns(_))
                        && Some(record.name.len()) == best_zone_length
                })
                .cloned()
                .collect()
        } else {
            Vec::new()
        };

        // Additional 区携带 NS 主机名对应的 A 记录（glue record）。
        let name_servers: Vec<&str> = authorities
            .iter()
            .filter_map(|record| match &record.data {
                DnsRecordData::Ns(name) => Some(name.as_str()),
                _ => None,
            })
            .collect();
        let additionals = self
            .records
            .iter()
            .filter(|record| {
                name_servers.contains(&record.name.as_str())
                    && matches!(record.data, DnsRecordData::A(_))
            })
            .cloned()
            .collect();

        Ok(UdpDatagram {
            src_port: DNS_PORT,
            dst_port: datagram.src_port,
            payload: UdpPayload::Dns(DnsMessage {
                id: query.id,
                is_response: true,
                questions: query.questions.clone(),
                answers,
                authorities,
                additionals,
            }),
        })
    }
}

// ========== Local Resolver 与 TTL Cache ==========
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CachedDnsRecord {
    pub ip: Ipv4Addr,
    pub ttl: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsExchange {
    pub server_name: String,
    pub query: IpPacket,
    pub response: IpPacket,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveResult {
    pub ip: Ipv4Addr,
    pub ttl: u32,
    pub cache_hit: bool,
    pub exchanges: Vec<DnsExchange>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DnsResolveError {
    MissingQuestion,
    WrongDestinationPort(u16),
    NoAnswer(String),
    InvalidResponse,
}

pub struct DnsResolver {
    pub client_ip: Ipv4Addr,
    pub source_port: u16,
    next_id: u16,
    cache: HashMap<String, CachedDnsRecord>,
}

impl DnsResolver {
    pub fn new(client_ip: Ipv4Addr, source_port: u16) -> Self {
        Self {
            client_ip,
            source_port,
            next_id: 1,
            cache: HashMap::new(),
        }
    }

    // Local Resolver 执行迭代查询。servers 按 Root → TLD → Authoritative 排列，
    // 每一步都真实构造 DNS → UDP → IP 查询和响应对象。
    pub fn resolve(
        &mut self,
        name: &str,
        servers: &[&DnsServer],
    ) -> Result<ResolveResult, DnsResolveError> {
        let name = normalize_name(name);
        if let Some(cached) = self
            .cache
            .get(&name)
            .copied()
            .filter(|record| record.ttl > 0)
        {
            return Ok(ResolveResult {
                ip: cached.ip,
                ttl: cached.ttl,
                cache_hit: true,
                exchanges: Vec::new(),
            });
        }

        let query_id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let mut exchanges = Vec::new();

        for server in servers {
            let query_message = DnsMessage::query(query_id, &name, DnsRecordType::A);
            let query_datagram = UdpDatagram {
                src_port: self.source_port,
                dst_port: DNS_PORT,
                payload: UdpPayload::Dns(query_message),
            };
            let query_packet = IpPacket {
                src: self.client_ip,
                dst: server.ip,
                ttl: 64,
                payload: IpPayload::Udp(query_datagram.clone()),
            };
            let response_datagram = server.handle_udp(&query_datagram)?;
            let response_packet = IpPacket {
                src: server.ip,
                dst: self.client_ip,
                ttl: 64,
                payload: IpPayload::Udp(response_datagram.clone()),
            };
            exchanges.push(DnsExchange {
                server_name: server.name.clone(),
                query: query_packet,
                response: response_packet,
            });

            let UdpPayload::Dns(response) = response_datagram.payload;
            if !response.is_response || response.id != query_id {
                return Err(DnsResolveError::InvalidResponse);
            }
            if let Some((ip, ttl)) = response
                .answers
                .iter()
                .find_map(|record| match record.data {
                    DnsRecordData::A(ip) if record.name == name => Some((ip, record.ttl)),
                    _ => None,
                })
            {
                self.cache.insert(name, CachedDnsRecord { ip, ttl });
                return Ok(ResolveResult {
                    ip,
                    ttl,
                    cache_hit: false,
                    exchanges,
                });
            }
        }

        Err(DnsResolveError::NoAnswer(name))
    }

    // 模拟一秒过去；DNS TTL 到 0 后缓存项失效。
    pub fn tick(&mut self) {
        self.cache.retain(|_, record| {
            record.ttl = record.ttl.saturating_sub(1);
            record.ttl > 0
        });
    }

    pub fn cached(&self, name: &str) -> Option<CachedDnsRecord> {
        self.cache.get(&normalize_name(name)).copied()
    }
}

fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn name_belongs_to_zone(name: &str, zone: &str) -> bool {
    name == zone || name.ends_with(&format!(".{zone}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hierarchy() -> (DnsServer, DnsServer, DnsServer) {
        let root = DnsServer::new(
            "Root",
            Ipv4Addr { value: 0xC000_0201 },
            vec![
                DnsRecord::ns("com", "a.gtld.test", 10),
                DnsRecord::a("a.gtld.test", Ipv4Addr { value: 0xC000_0202 }, 10),
            ],
        );
        let tld = DnsServer::new(
            ".com TLD",
            Ipv4Addr { value: 0xC000_0202 },
            vec![
                DnsRecord::ns("tinynet.com", "ns.tinynet.com", 10),
                DnsRecord::a("ns.tinynet.com", Ipv4Addr { value: 0xC000_0203 }, 10),
            ],
        );
        let authoritative = DnsServer::new(
            "Authoritative",
            Ipv4Addr { value: 0xC000_0203 },
            vec![DnsRecord::a(
                "www.tinynet.com",
                Ipv4Addr { value: 0x0A00_0008 },
                3,
            )],
        );
        (root, tld, authoritative)
    }

    #[test]
    fn resolver_walks_hierarchy_then_hits_cache() {
        let (root, tld, authoritative) = hierarchy();
        let servers = [&root, &tld, &authoritative];
        let mut resolver = DnsResolver::new(Ipv4Addr { value: 0xC0A8_0102 }, 53_000);

        let first = resolver.resolve("www.tinynet.com", &servers).unwrap();
        assert_eq!(first.ip, Ipv4Addr { value: 0x0A00_0008 });
        assert_eq!(first.exchanges.len(), 3);
        assert!(!first.cache_hit);
        let second = resolver.resolve("www.tinynet.com", &servers).unwrap();
        assert!(second.cache_hit);
        assert!(second.exchanges.is_empty());
    }

    #[test]
    fn cache_entry_expires_after_dns_ttl_ticks() {
        let (root, tld, authoritative) = hierarchy();
        let servers = [&root, &tld, &authoritative];
        let mut resolver = DnsResolver::new(Ipv4Addr { value: 0xC0A8_0102 }, 53_000);
        resolver.resolve("www.tinynet.com", &servers).unwrap();
        resolver.tick();
        resolver.tick();
        assert_eq!(resolver.cached("www.tinynet.com").unwrap().ttl, 1);
        resolver.tick();
        assert!(resolver.cached("www.tinynet.com").is_none());
    }
}
