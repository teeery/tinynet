use std::collections::HashMap;

use crate::tcp::{TcpConnection, TcpSegment, TcpState};

// ========== v0.7：Mini HTTP/1.1 消息 ==========
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: HttpMethod,
    pub path: String,
    pub host: String,
}

impl HttpRequest {
    pub fn get(host: &str, path: &str) -> Self {
        Self {
            method: HttpMethod::Get,
            path: path.to_string(),
            host: host.to_string(),
        }
    }

    // HTTP 定义消息格式，TCP 只会看到这里产生的字节流。
    pub fn to_bytes(&self) -> Vec<u8> {
        format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n",
            self.path, self.host
        )
        .into_bytes()
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "HTTP 请求不是 UTF-8")?;
        let header = text
            .split_once("\r\n\r\n")
            .map(|(header, _)| header)
            .ok_or("HTTP 请求缺少空行")?;
        let mut lines = header.lines();
        let request_line = lines.next().ok_or("缺少 HTTP 请求行")?;
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() != 3 || parts[0] != "GET" || parts[2] != "HTTP/1.1" {
            return Err("只支持 GET ... HTTP/1.1".to_string());
        }
        let host = lines
            .find_map(|line| line.strip_prefix("Host:").map(str::trim))
            .ok_or("缺少 Host 首部")?;
        Ok(Self::get(host, parts[1]))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponse {
    pub status_code: u16,
    pub reason: String,
    pub body: String,
}

impl HttpResponse {
    pub fn to_bytes(&self) -> Vec<u8> {
        format!(
            "HTTP/1.1 {} {}\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{}",
            self.status_code,
            self.reason,
            self.body.len(),
            self.body
        )
        .into_bytes()
    }

    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let text = std::str::from_utf8(bytes).map_err(|_| "HTTP 响应不是 UTF-8")?;
        let (header, body) = text.split_once("\r\n\r\n").ok_or("HTTP 响应缺少空行")?;
        let status_line = header.lines().next().ok_or("缺少 HTTP 状态行")?;
        let mut parts = status_line.splitn(3, ' ');
        if parts.next() != Some("HTTP/1.1") {
            return Err("只支持 HTTP/1.1 响应".to_string());
        }
        let status_code = parts
            .next()
            .ok_or("缺少状态码")?
            .parse()
            .map_err(|_| "非法状态码")?;
        let reason = parts.next().ok_or("缺少原因短语")?.to_string();
        Ok(Self {
            status_code,
            reason,
            body: body.to_string(),
        })
    }
}

// ========== HTTP Server ==========
pub struct HttpServer {
    pub host: String,
    pub resources: HashMap<String, String>,
}

impl HttpServer {
    pub fn new(host: &str) -> Self {
        Self {
            host: host.to_string(),
            resources: HashMap::new(),
        }
    }

    pub fn add_resource(&mut self, path: &str, body: &str) {
        self.resources.insert(path.to_string(), body.to_string());
    }

    pub fn handle(&self, request: &HttpRequest) -> HttpResponse {
        if request.host != self.host {
            return not_found();
        }
        match self.resources.get(&request.path) {
            Some(body) => HttpResponse {
                status_code: 200,
                reason: "OK".to_string(),
                body: body.clone(),
            },
            None => not_found(),
        }
    }
}

fn not_found() -> HttpResponse {
    HttpResponse {
        status_code: 404,
        reason: "Not Found".to_string(),
        body: String::new(),
    }
}

// ========== HTTP over existing TcpConnection ==========
#[derive(Clone, Debug)]
pub struct HttpExchange {
    pub request: HttpRequest,
    pub response: HttpResponse,
    pub request_segments: Vec<TcpSegment>,
    pub response_segments: Vec<TcpSegment>,
}

pub struct HttpSession {
    pub tcp_client: TcpConnection,
    pub tcp_server: TcpConnection,
    pub http_server: HttpServer,
    pub handshake_count: u32,
    pub request_count: u32,
    mss: usize,
}

impl HttpSession {
    pub fn new(http_server: HttpServer, client_port: u16) -> Self {
        Self {
            tcp_client: TcpConnection::client("HTTP Client", client_port, 80, 10_000, 8192, 8192),
            tcp_server: TcpConnection::listener("HTTP Server", 80, 20_000, 8192, 8192),
            http_server,
            handshake_count: 0,
            request_count: 0,
            mss: 1460,
        }
    }

    // 返回三次握手的三个报文，方便 demo 展示；连接已建立时不会再次握手。
    pub fn connect(&mut self) -> Result<Vec<TcpSegment>, String> {
        if self.tcp_client.state == TcpState::Established
            && self.tcp_server.state == TcpState::Established
        {
            return Ok(Vec::new());
        }
        let syn = self.tcp_client.connect()?;
        let syn_ack = self
            .tcp_server
            .receive(syn.clone())?
            .ok_or("Server 未返回 SYN+ACK")?;
        let ack = self
            .tcp_client
            .receive(syn_ack.clone())?
            .ok_or("Client 未返回 ACK")?;
        self.tcp_server.receive(ack.clone())?;
        self.handshake_count += 1;
        Ok(vec![syn, syn_ack, ack])
    }

    pub fn get(&mut self, path: &str) -> Result<HttpExchange, String> {
        if self.tcp_client.state != TcpState::Established
            || self.tcp_server.state != TcpState::Established
        {
            return Err("HTTP 请求前必须先建立 TCP 连接".to_string());
        }

        let request = HttpRequest::get(&self.http_server.host, path);
        let request_bytes = request.to_bytes();
        let request_segments = self.tcp_client.send_data(&request_bytes, self.mss)?;
        ensure_all_bytes_sent(&request_segments, request_bytes.len())?;
        for segment in request_segments.iter().cloned() {
            let ack = self
                .tcp_server
                .receive(segment)?
                .ok_or("Server 未确认 HTTP 请求字节")?;
            self.tcp_client.receive(ack)?;
        }
        let server_bytes = self.tcp_server.application_read(usize::MAX);
        // 应用读取后立即通告恢复的窗口，避免持久连接越用窗口越小。
        self.tcp_client.receive(self.tcp_server.window_update()?)?;
        let parsed_request = HttpRequest::parse(&server_bytes)?;
        let server_response = self.http_server.handle(&parsed_request);

        let response_bytes = server_response.to_bytes();
        let response_segments = self.tcp_server.send_data(&response_bytes, self.mss)?;
        ensure_all_bytes_sent(&response_segments, response_bytes.len())?;
        for segment in response_segments.iter().cloned() {
            let ack = self
                .tcp_client
                .receive(segment)?
                .ok_or("Client 未确认 HTTP 响应字节")?;
            self.tcp_server.receive(ack)?;
        }
        let client_bytes = self.tcp_client.application_read(usize::MAX);
        self.tcp_server.receive(self.tcp_client.window_update()?)?;
        let response = HttpResponse::parse(&client_bytes)?;
        self.request_count += 1;

        Ok(HttpExchange {
            request,
            response,
            request_segments,
            response_segments,
        })
    }

    pub fn close(&mut self) -> Result<(), String> {
        let client_fin = self.tcp_client.close()?;
        let server_ack = self
            .tcp_server
            .receive(client_fin)?
            .ok_or("Server 未确认 FIN")?;
        self.tcp_client.receive(server_ack)?;
        let server_fin = self.tcp_server.close()?;
        let final_ack = self
            .tcp_client
            .receive(server_fin)?
            .ok_or("Client 未返回最终 ACK")?;
        self.tcp_server.receive(final_ack)?;
        self.tcp_client.expire_time_wait()?;
        Ok(())
    }
}

fn ensure_all_bytes_sent(segments: &[TcpSegment], expected: usize) -> Result<(), String> {
    let actual: usize = segments.iter().map(|segment| segment.payload.len()).sum();
    if actual == expected {
        Ok(())
    } else {
        Err(format!("TCP 窗口只允许发送 {actual}/{expected} 字节"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trip_proves_http_is_a_byte_protocol() {
        let request = HttpRequest::get("www.tinynet.com", "/index.html");
        assert_eq!(HttpRequest::parse(&request.to_bytes()).unwrap(), request);
    }

    #[test]
    fn server_returns_200_and_404() {
        let mut server = HttpServer::new("www.tinynet.com");
        server.add_resource("/index.html", "<h1>TinyNet</h1>");
        assert_eq!(
            server
                .handle(&HttpRequest::get("www.tinynet.com", "/index.html"))
                .status_code,
            200
        );
        assert_eq!(
            server
                .handle(&HttpRequest::get("www.tinynet.com", "/missing"))
                .status_code,
            404
        );
    }

    #[test]
    fn persistent_session_reuses_one_tcp_handshake() {
        let mut server = HttpServer::new("www.tinynet.com");
        server.add_resource("/index.html", "<h1>TinyNet</h1>");
        server.add_resource("/hello.txt", "hello network");
        let mut session = HttpSession::new(server, 50_000);
        assert_eq!(session.connect().unwrap().len(), 3);
        assert_eq!(
            session.get("/index.html").unwrap().response.status_code,
            200
        );
        assert_eq!(session.get("/missing").unwrap().response.status_code, 404);
        assert_eq!(session.get("/hello.txt").unwrap().response.status_code, 200);
        assert!(session.connect().unwrap().is_empty());
        assert_eq!(session.handshake_count, 1);
        assert_eq!(session.request_count, 3);
        session.close().unwrap();
        assert_eq!(session.tcp_client.state, TcpState::Closed);
        assert_eq!(session.tcp_server.state, TcpState::Closed);
    }
}
