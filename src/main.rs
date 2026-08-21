mod address;
mod bgp;
mod chat;
mod demo;
mod dns;
mod host;
mod http;
pub mod icmp;
mod internet;
mod network;
mod ospf;
pub mod packet;
mod reliable;
mod routing;
mod switch;
mod tcp;
mod traceroute;
mod udp;

use std::io::{self, Write};

fn main() {
    println!("TinyNet v1.0 — 交互式网络实验");
    println!("一次只运行一个版本，实验结束后会返回菜单。\n");

    loop {
        print_menu();
        print!("请选择实验 [1-9，q 退出]：");
        // prompt 没有换行，需要立即刷新到终端。
        io::stdout().flush().expect("无法刷新终端输出");

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(0) => break, // stdin 已关闭，例如管道输入结束。
            Ok(_) => {}
            Err(error) => {
                eprintln!("读取输入失败：{error}");
                continue;
            }
        }

        let selection = input.trim().to_ascii_lowercase();
        if matches!(selection.as_str(), "q" | "quit" | "exit" | "0") {
            println!("已退出 TinyNet。");
            break;
        }

        println!();
        if run_selected_demo(&selection) {
            println!("\n实验运行完毕，按菜单选择其他版本。\n");
        } else {
            println!("无效选项：{selection:?}，请输入 1～9。\n");
        }
    }
}

fn print_menu() {
    println!("┌──────────────── TinyNet Labs ────────────────┐");
    println!("│ 1  v0.1  Packet 穿越节点                    │");
    println!("│ 2  v0.2  Ethernet LAN                       │");
    println!("│ 3  v0.3  IP Internet                        │");
    println!("│ 4  v0.4  可靠传输（GBN / SR）               │");
    println!("│ 5  v0.5  TCP                                │");
    println!("│ 6  v0.6  ARP / ICMP / ping / traceroute     │");
    println!("│ 7  v0.7  DNS + Mini HTTP                    │");
    println!("│ 8  v1.0  Mini Internet（Browser + Chat）     │");
    println!("│ 9  扩展   OSPF + BGP                         │");
    println!("│ q  退出                                      │");
    println!("└──────────────────────────────────────────────┘");
}

// 同时接受菜单编号和版本号，方便输入 `3` 或 `v0.3`。
fn run_selected_demo(selection: &str) -> bool {
    match selection {
        "1" | "v0.1" | "0.1" => demo::demo_v01_packet_forwarding(),
        "2" | "v0.2" | "0.2" => demo::demo_v02_ethernet_lan(),
        "3" | "v0.3" | "0.3" => demo::demo_v03_ip_internet(),
        "4" | "v0.4" | "0.4" => demo::demo_v04_reliable_transport(),
        "5" | "v0.5" | "0.5" => demo::demo_v05_tcp(),
        "6" | "v0.6" | "0.6" => demo::demo_v06_internet_diagnostics(),
        "7" | "v0.7" | "0.7" => demo::demo_v07_application_layer(),
        "8" | "v1.0" | "1.0" => demo::demo_v10_mini_internet(),
        "9" | "ext" | "extensions" => demo::demo_routing_extensions(),
        _ => return false,
    }
    true
}
