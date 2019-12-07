extern crate base64;
extern crate code;
extern crate crossbeam;

use std::fmt::Debug;

use async_std::io;
use async_std::io::{Read,Write};
use async_std::net::TcpStream;

use code::config::{IdentitySecret,ssb_net_id};
use code::asynchandshake::AsyncHandshake;
use code::asyncrpc::{Header,RequestNo,RpcClient};
use code::asyncapi::*;


async fn print_async<'a,R,W,T,F> (client: &mut ApiClient<R,W>, req_no : RequestNo, f : F) -> io::Result<()>
where
    R: Read+Unpin,
    W: Write+Unpin,
    F: Fn(&Header,&Vec<u8>)->io::Result<T>,
    T: Debug+serde::Deserialize<'a>
{
    loop {
        let (header,body) = client.rpc().recv().await?;
        if header.req_no == req_no {
            match f(&header,&body) {
                Ok(res) =>  println!("{:?}",res), 
                Err(err) => println!("*failed* {:?}",err)
            }
            break;
        }
    }
    Ok(())
}

async fn print_source_until_eof<'a,R,W,T,F> (client: &mut ApiClient<R,W>, req_no : RequestNo, f : F) -> io::Result<()>
where
    R: Read+Unpin,
    W: Write+Unpin,
    F: Fn(&Header,&Vec<u8>)->io::Result<T>,
    T: Debug+serde::Deserialize<'a>
{
    loop {
        let (header,body) = client.rpc().recv().await?;
        if header.req_no == req_no {
            if !header.is_end_or_error {
                println!("{}",String::from_utf8_lossy(&body));
                match f(&header,&body) {
                    Ok(res) =>  println!("{:?}",res), 
                    Err(err) => { println!("{:?}",err); }
                }
            } else {
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

    let mut client = ApiClient::new(RpcClient::new(box_stream_read, box_stream_write));

    let mut line_buffer = String::new();
    while let Ok(_) = std::io::stdin().read_line(&mut line_buffer) {

        let args : Vec<String> = line_buffer
            .replace("\n", "")
            .split_whitespace()
            .map(|arg| arg.to_string())
            .collect();

        match (args[0].as_str(), args.len()) {
            ("exit",1) => {
                client.rpc().close().await?;
                break;
            }
            ("whoami",1) => {
                let req_id = client.send_whoami().await?;
                print_async(&mut client,-req_id,parse_whoami).await?;
            }
            ("get",2) => {
                let msg_id = if args[1] == "0" {
                    "%TL34NIX8JpMJN+ubHWx6cRhIwEal8VqHdKVg2t6lFcg=.sha256".to_string()
                } else {
                    args[1].clone()
                };
                let req_id = client.send_get(&msg_id).await?;
                print_async(&mut client,-req_id,parse_message).await?;
            }
            ("user",2) => {
                let user_id = if args[1] == "0" {
                    "@ZFWw+UclcUgYi081/C8lhgH+KQ9s7YJRoOYGnzxW/JQ=.ed25519".to_string()
                } else {
                    args[1].clone()
                };

                let args = CreateHistoryStreamArgs::new(&user_id);
                let req_id = client.send_create_history_stream(&args).await?;
                print_source_until_eof(&mut client, -req_id, parse_feed).await?;
            }
            ("feed",1) => {
                let args = CreateStreamArgs::default();
                let req_id = client.send_create_feed_stream(&args).await?;
                print_source_until_eof(&mut client, -req_id, parse_feed).await?;
            }
            ("latest",1) => {
                let req_id = client.send_latest().await?;
                print_source_until_eof(&mut client, -req_id, parse_latest).await?;
            }
            _ => println!("unknown command {}",line_buffer),
        }
        line_buffer.clear();
    }
    Ok(())
}