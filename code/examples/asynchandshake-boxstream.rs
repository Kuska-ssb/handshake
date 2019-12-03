extern crate base64;
extern crate code;
extern crate crossbeam;

use log::debug;
use sodiumoxide::crypto::{auth, sign::ed25519};
use std::env;
use async_std::net::{TcpListener, TcpStream};
use async_std::io;
use async_std::prelude::*;

use code::asynchandshake::{AsyncHandshake, SharedSecret};

fn usage(arg0: &str) {
    eprintln!(
        "Usage: {0} [client/server] OPTS
    client OPTS: addr server_pk
    server OPTS: addr",
        arg0
    );
}

fn print_shared_secret(shared_secret: &SharedSecret) {
    debug!("shared_secret {{");
    debug!("  ab: {}", hex::encode(shared_secret.ab.as_ref()));
    debug!("  aB: {}", hex::encode(shared_secret.aB.as_ref()));
    debug!("  Ab: {}", hex::encode(shared_secret.Ab.as_ref()));
    debug!("}}");
}

async fn test_server(
    socket: TcpStream,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
) -> io::Result<()> {
    let handshake = AsyncHandshake::new_server(&socket, &socket, net_id, pk, sk)
        .recv_client_hello().await?
        .send_server_hello().await?
        .recv_client_auth().await?
        .send_server_accept().await?;
    println!("Handshake complete! 💃");
    debug!("{:#?}", handshake);
    print_shared_secret(&handshake.state.shared_secret);

    let (mut box_stream_read, mut box_stream_write) =
        handshake.to_box_stream(0x8000).split_read_write();
    
    // echo server
    let mut buffer = [0;128];
    loop {
        match box_stream_read.read(&mut buffer[..]).await {
            Ok(n) => {
                if n == 0 {
                    break
                }
                let message = String::from_utf8_lossy(&buffer[..n]);
                println!("recieved {}", message);
                let response = format!("Hello {}",message);
                box_stream_write.write_all(&response.as_bytes()).await?;
                box_stream_write.flush().await?;
            }
            Err(err) => {
                panic!("{}",err);
            }
        }
    }
    println!("Connection finished");
    Ok(())
}

async fn test_client(
    socket: TcpStream,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
    server_pk: ed25519::PublicKey,
) -> io::Result<()> {
    let handshake = AsyncHandshake::new_client(&socket, &socket, net_id, pk, sk)
        .send_client_hello().await?
        .recv_server_hello().await?
        .send_client_auth(server_pk).await?
        .recv_server_accept().await?;
    println!("Handshake complete! 💃");
    debug!("{:#?}", handshake);
    print_shared_secret(&handshake.state.shared_secret);

    let (mut box_stream_read, mut box_stream_write) =
        handshake.to_box_stream(0x8000).split_read_write();

    let mut buffer = [0;128];
    // repl
    let mut line_buffer = String::new();
    while let Ok(_) = std::io::stdin().read_line(&mut line_buffer) {
        box_stream_write.write_all(&line_buffer.as_bytes()).await?;
        box_stream_write.flush().await?;
        match box_stream_read.read(&mut buffer[..]).await {
            Ok(n) => {
                if n == 0 {
                    break
                }
                let message = String::from_utf8_lossy(&buffer[..n]);
                println!("SERVER SAYS: {}", message);
                line_buffer.clear();
            }
            Err(err) => {
                panic!("{}",err);
            }
        }
    }
    Ok(())
}

#[async_std::main]
async fn main() -> io::Result<()> {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage(&args[0]);
        return Ok(());
    }
    let net_id_hex = "d4a1cb88a66f02f8db635ce26441cc5dac1b08420ceaac230839b755845a9ffb";
    let net_id = auth::Key::from_slice(&hex::decode(net_id_hex).unwrap()).unwrap();

    let (pk, sk) = ed25519::gen_keypair();
    let pk_b64 = base64::encode_config(&pk, base64::STANDARD);
    println!("Public key: {}", pk_b64);

    match args[1].as_str() {
        "client" => {
            if args.len() < 4 {
                usage(&args[0]);
                return Ok(());
            }
            let server_pk_buf = base64::decode_config(args[3].as_str(), base64::STANDARD).unwrap();
            let server_pk = ed25519::PublicKey::from_slice(&server_pk_buf).unwrap();
            let socket = TcpStream::connect(args[2].as_str()).await?;
            test_client(socket, net_id, pk, sk, server_pk).await
        }
        "server" => {
            if args.len() < 3 {
                usage(&args[0]);
                return Ok(());
            }
            let listener = TcpListener::bind(args[2].as_str()).await?;
            println!(
                "Listening for a handshake via TCP at {} ...",
                args[2].as_str()
            );
            let (socket, addr) = listener.accept().await?;
            println!("Client {} connected", addr);
            test_server(socket, net_id, pk, sk).await
        }
        _ => Ok(()),
    }
}
