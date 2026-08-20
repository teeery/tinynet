mod address;
pub mod packet;
mod host;
mod switch;
mod routing;
mod ospf;
mod bgp;
mod demo;
mod reliable;
mod tcp;
pub mod icmp;
mod traceroute;

fn main() {
    demo::demo_v01();
    demo::demo_v02();
    demo::demo_v03();
    demo::demo_v04();
    demo::demo_v05();
    demo::demo_v04_reliable_transport();
    demo::demo_v05_tcp();
    demo::demo_v06_ping_same_lan();
    demo::demo_v06_ping_across_router();
    demo::demo_v06_traceroute();
    demo::demo_v06();
    demo::demo_v07();
}
