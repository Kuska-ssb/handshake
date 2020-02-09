extern crate base64;
extern crate kuska_handshake;

use async_std::io;
use async_std::net::{TcpListener, TcpStream};
use std::env;

use sodiumoxide::crypto::{auth, sign::ed25519};

use kuska_handshake::async_std::{handshake_client, handshake_server, BoxStream, Error};

const BUF_SIZE: usize = 0x8000;

#[async_std::main]
async fn main() -> Result<(), Error> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} [client/server] address [--buf]", args[0]);
        return Ok(());
    }
    let mode = args[1].as_str();
    let addr = args[2].as_str();
    let mut buffered = false;
    if args.len() > 3 {
        if args[3].as_str() == "--buf" {
            eprintln!("Using BufReader and BufWriter");
            buffered = true;
        }
    }

    let net_id_hex = "d4a1cb88a66f02f8db635ce26441cc5dac1b08420ceaac230839b755845a9ffb";
    let net_id = auth::Key::from_slice(&hex::decode(net_id_hex).unwrap()).unwrap();

    let client_seed_hex = "0000000000000000000000000000000000000000000000000000000000000000";
    let (client_pk, client_sk) = ed25519::keypair_from_seed(
        &ed25519::Seed::from_slice(&hex::decode(client_seed_hex).unwrap()).unwrap(),
    );

    let server_seed_hex = "0000000000000000000000000000000000000000000000000000000000000001";
    let (server_pk, server_sk) = ed25519::keypair_from_seed(
        &ed25519::Seed::from_slice(&hex::decode(server_seed_hex).unwrap()).unwrap(),
    );

    let (handshake, socket) = match mode {
        "client" => {
            let mut socket = TcpStream::connect(addr).await?;

            let handshake =
                handshake_client(&mut socket, net_id, client_pk, client_sk, server_pk).await?;
            (handshake, socket)
        }
        "server" => {
            let listener = TcpListener::bind(addr).await?;
            let (mut socket, _) = listener.accept().await?;

            let handshake = handshake_server(&mut socket, net_id, server_pk, server_sk).await?;
            (handshake, socket)
        }
        _ => {
            eprintln!("Usage: {} [client/server] address", args[0]);
            return Ok(());
        }
    };

    let (mut box_stream_read, mut box_stream_write) =
        BoxStream::from_handshake(&socket, &socket, handshake, 0x8000).split_read_write();

    match mode {
        "client" => {
            // stdin -> boxstream
            if buffered {
                io::copy(
                    &mut io::BufReader::with_capacity(BUF_SIZE, &mut io::stdin()),
                    &mut io::BufWriter::with_capacity(BUF_SIZE, &mut box_stream_write),
                )
                .await?;
            } else {
                io::copy(&mut io::stdin(), &mut box_stream_write).await?;
            }
        }
        "server" => {
            // boxstream -> stdout
            if buffered {
                io::copy(
                    &mut io::BufReader::with_capacity(BUF_SIZE, &mut box_stream_read),
                    &mut io::BufWriter::with_capacity(BUF_SIZE, &mut io::stdout()),
                )
                .await?;
            } else {
                io::copy(&mut box_stream_read, &mut io::stdout()).await?;
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
