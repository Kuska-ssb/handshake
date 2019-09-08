extern crate get_if_addrs;

use get_if_addrs::get_if_addrs;
use std::thread;
use std::time::Duration;
use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:8008")?;
    socket.set_broadcast(true)?;
    let socket_broadcast = socket.try_clone().unwrap();
    let pk_b64 = "12pEBBxd0g++furqcMvwtWFRZubL8R0F++T3uLm2TV8=";
    let handle_broadcast = thread::spawn(move || {
        loop {
            for iface in get_if_addrs().unwrap() {
                if iface.addr.is_loopback() {
                    continue;
                }
                let msg = format!("net:{}:8008~shs:{}", iface.addr.ip(), pk_b64);
                socket_broadcast.send_to(msg.as_bytes(), "255.255.255.255:8008").unwrap();
            }
            thread::sleep(Duration::from_secs(1));
        }
    });
    let handle_listen = thread::spawn(move || {
        loop {
            let mut buf = [0; 128];
            let (amt, src) = socket.recv_from(&mut buf).unwrap();
            println!("> {:?}", String::from_utf8(buf[..amt].to_vec()));
        }
    });
    handle_broadcast.join().unwrap();
    handle_listen.join().unwrap();
    Ok(())
}
