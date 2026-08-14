mod address;
mod packet;
mod host;
mod switch;
mod routing;
mod ospf;
mod demo;

fn main() {
    demo::demo_v01();
    demo::demo_v02();
    demo::demo_v03();
    demo::demo_v04();
    demo::demo_v05();
    demo::demo_v06();
}
