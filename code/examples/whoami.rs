extern crate base64;
extern crate code;
extern crate crossbeam;

use std::io;
use async_std::net::{TcpStream,Shutdown};

use code::config::{IdentitySecret,ssb_net_id};
use code::asynchandshake::AsyncHandshake;
use code::asyncrpc;

#[async_std::main]
async fn main() -> io::Result<()> {

    env_logger::init();
    log::set_max_level(log::LevelFilter::max());

    let IdentitySecret{pk,sk,..} = IdentitySecret::from_local_config()
        .expect("read local secret");

    let socket = TcpStream::connect("127.0.0.1:8008").await?;

    let handshake = AsyncHandshake::new_client(&socket, &socket, ssb_net_id(), pk, sk)
        .send_client_hello().await?
        .recv_server_hello().await?
        .send_client_auth(pk).await?
        .recv_server_accept().await?;

    println!("💃 handshake complete");

    let (box_stream_read, box_stream_write) =
        handshake.to_box_stream(0x8000).split_read_write();

    let mut client = asyncrpc::Client::new(box_stream_read, box_stream_write);
    let req_no = client.send_whoami().await?;

    let mut whoami = None;
    while whoami.is_none() {
        let (header,body) = client.recv().await?;
        if header.req_no == -req_no {
            let parsed = client.parse_whoami(&header,&body)?;
            whoami = Some(parsed); 
        }
    }
    client.close().await?;
    
    println!("{}", whoami.unwrap().id);
    Ok(())
}