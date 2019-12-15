extern crate base64;
extern crate code;
extern crate crossbeam;

use std::env;
use std::io::{self};
use std::net::{TcpListener, TcpStream};

use crossbeam::thread;
use log::debug;
use sodiumoxide::crypto::{auth, sign::ed25519};

use code::boxstream::{BoxStream, KeyNonce};
use code::handshake::SharedSecret;
use code::handshake_sync::{self, handshake_client, handshake_server};

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} [client/server] address", args[0]);
        return;
    }
    let mode = args[1].as_str();
    let addr = args[2].as_str();

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
            let socket = TcpStream::connect(addr).unwrap();

            let handshake =
                handshake_client(&socket, net_id, client_pk, client_sk, server_pk).unwrap();
            (handshake, socket)
        }
        "server" => {
            let listener = TcpListener::bind(addr).unwrap();
            let (socket, addr) = listener.accept().unwrap();

            let handshake = handshake_server(&socket, net_id, server_pk, server_sk).unwrap();
            (handshake, socket)
        }
        _ => {
            eprintln!("Usage: {} [client/server] address", args[0]);
            return;
        }
    };

    let (key_nonce_send, key_nonce_recv) = KeyNonce::from_handshake(handshake);
    let (mut box_stream_read, mut box_stream_write) =
        BoxStream::new(&socket, &socket, 0x8000, key_nonce_send, key_nonce_recv).split_read_write();

    match mode {
        "client" => {
            // stdin -> boxstream
            io::copy(&mut io::stdin(), &mut box_stream_write).unwrap();
        }
        "server" => {
            // boxstream -> stdout
            io::copy(&mut box_stream_read, &mut io::stdout()).unwrap();
        }
        _ => unreachable!(),
    }
}
