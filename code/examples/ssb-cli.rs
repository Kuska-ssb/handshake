extern crate base64;
extern crate code;
extern crate crossbeam;

use async_std::io;
use async_std::io::{Read,Write};
use async_std::prelude::*;
use async_std::net::TcpStream;

use code::config::{IdentitySecret,ssb_net_id};
use code::asynchandshake::AsyncHandshake;
use code::asyncrpc::{Header,RequestNo,Client,CreateHistoryStreamArgs};

async fn wait_msg<R:Read+Unpin,W:Write+Unpin> (client: &mut Client<R,W>, req_no : RequestNo) -> io::Result<(Header,Vec<u8>)> {
    loop {
        let (header,body) = client.recv().await?;
        if header.req_no == req_no {
            return Ok((header,body))
        }
    }
}
async fn read_all_until_eof<R:Read+Unpin,W:Write+Unpin> (client: &mut Client<R,W>, req_no : RequestNo) -> io::Result<()> {
    loop {
        let (header,body) = client.recv().await?;
        if header.req_no == req_no {
            println!("{}",String::from_utf8_lossy(&body));
            if header.is_end_or_error {
                println!("STREAM FINISHED");
                return Ok(())
            }
        }
    }
}

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

    let mut client = Client::new(box_stream_read, box_stream_write);

    let mut line_buffer = String::new();
    while let Ok(_) = std::io::stdin().read_line(&mut line_buffer) {

        let args : Vec<String> = line_buffer
            .replace("\n", "")
            .split_whitespace()
            .map(|arg| arg.to_string())
            .collect();

        match (args[0].as_str(), args.len()) {
            ("exit",1) => {
                client.close().await?;
                break;
            }
            ("whoami",1) => {
                let req_id = client.send_whoami().await?;
                let (h,b) = wait_msg(&mut client, -req_id).await?;
                let whoami = client.parse_whoami(&h,&b)?;

                println!("reponse: {}",whoami.id);
            }
            ("get",2) => {
                let msg_id = if args[1] == "0" {
                    "%TL34NIX8JpMJN+ubHWx6cRhIwEal8VqHdKVg2t6lFcg=.sha256".to_string()
                } else {
                    args[1].clone()
                };
                let req_id = client.send_get(&msg_id).await?;
                let (h,b) = wait_msg(&mut client, -req_id).await?;
                let msg = client.parse_get(&h,&b)?;
                println!("reponse: {:?}",msg);
            }
            ("history",2) => {

                let feed_id = if args[1] == "0" {
                    "@N/vWpVVdD1e8IbACUQE4EVGL6+aodQfbQZ8ByC+k79s=.ed25519".to_string()
                } else {
                    args[1].clone()
                };

                let args = CreateHistoryStreamArgs {
                    id     : &feed_id,
                    seq    : Some(1),
                    live   : None,    
                    keys   : None,
                    values : None,
                    limit  : None,
                };
                let req_id = client.send_create_history_stream(&args).await?;
                read_all_until_eof(&mut client, -req_id).await?;
            }
            _ => println!("unknown command {}",line_buffer),
        }
        line_buffer.clear();
    }
    Ok(())
}