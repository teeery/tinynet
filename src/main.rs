use std::collections::HashMap;
use std::rc::Rc;

//数据包
struct Packet {
    src: String, //源地址
    dst: String, //目的地址
    data: String, //数据
}

impl Packet {
    fn new(src: &str, dst: &str, data: &str) -> Self {
        Packet { 
            src: src.to_string(), 
            dst: dst.to_string(), 
            data: data.to_string() 
        }
    }
}

//主机
struct Host {
    name: String,
}

impl Host {
    fn new(name: &str) -> Self {
        Host { name: name.to_string() }
    }
    fn send(&self, packet: Packet, router: &Router) {
        println!("[{}] 发送数据包", self.name);
        router.forward(packet);
    }
    fn receive(&self, packet: Packet) {
        println!("[{}] 收到数据包: {}", self.name, packet.data);
    }
}

//路由器
struct Router{
    routes: HashMap<String, Rc<Host>>, //路由表：存“目的地址->对应主机”
}

impl Router {
    fn new() -> Self {
        Router { routes: HashMap::new() }
    }
    fn add_route(&mut self,destination:&str,host:Rc<Host>){
        self.routes.insert(destination.to_string(), host);
    }
    fn forward(&self,packet: Packet){
        println!("[路由器] 转发 {} -> {}", packet.src, packet.dst);
        match self.routes.get(&packet.dst){
            Some(host) => {
                host.receive(packet);
            },
            None => {
                println!("[路由器] 无法到达目的地: {}", packet.dst);
            }
        }
    }
}

fn main() {
    let alice = Rc::new(Host::new("主机A"));
    let bob = Rc::new(Host::new("主机B"));

    let mut router = Router::new();
    router.add_route("主机B", Rc::clone(&bob));

    let packet = Packet::new("主机A", "主机B", "早上好, 主机B!");
    alice.send(packet, &router);
}