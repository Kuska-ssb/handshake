use std::thread;
use std::time::Duration;
use std::net::UdpSocket;

fn main() -> std::io::Result<()> {
    let mut socket = UdpSocket::bind("0.0.0.0:8008")?;
    let msg = "HELLO WORLD!";
    loop {
        socket.send_to(msg.as_bytes(), "255.255.255.255:8008").unwrap();
        thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

