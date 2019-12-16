extern crate base64;
extern crate code;
extern crate crossbeam;

use std::env;
use std::io::{self};
use std::net::{TcpListener, TcpStream};

use crossbeam::thread;
use log::debug;
use sodiumoxide::crypto::{auth, sign::ed25519};

use code::boxstream::KeyNonce;
use code::boxstream_sync::BoxStream;
use code::handshake::SharedSecret;
use code::handshake_sync::{self, handshake_client, handshake_server};

fn usage(arg0: &str) {
    eprintln!(
        "Usage: {0} [client/server] OPTS
    client OPTS: addr server_pk
    server OPTS: addr",
        arg0
    );
}

fn print_shared_secret(shared_secret: &SharedSecret) {
    println!("shared_secret {{");
    println!("  ab: {}", hex::encode(shared_secret.ab.as_ref()));
    println!("  aB: {}", hex::encode(shared_secret.aB.as_ref()));
    println!("  Ab: {}", hex::encode(shared_secret.Ab.as_ref()));
    println!("}}");
}

fn test_server(
    socket: TcpStream,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
) -> handshake_sync::Result<()> {
    let handshake = handshake_server(&socket, net_id, pk, sk)?;
    println!("Handshake complete! 💃");
    debug!("{:#?}", handshake);
    print_shared_secret(&handshake.shared_secret);

    let (key_nonce_send, key_nonce_recv) = KeyNonce::from_handshake(handshake);
    let (mut box_stream_read, mut box_stream_write) =
        BoxStream::new(&socket, &socket, key_nonce_send, key_nonce_recv).split_read_write();

    thread::scope(|s| {
        let handle = s.spawn(move |_| io::copy(&mut box_stream_read, &mut io::stdout()).unwrap());
        io::copy(&mut io::stdin(), &mut box_stream_write).unwrap();
        handle.join().unwrap();
    })
    .unwrap();
    // box_stream.write(b"I'm the server")?;
    // box_stream.flush()?;
    // let mut buf = [0; 0x1000];
    // let n = box_stream.read(&mut buf)?;
    // println!("Received:");
    // io::stdout().write_all(&buf[..n])?;
    // println!();
    Ok(())
}

fn test_client(
    socket: TcpStream,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
    server_pk: ed25519::PublicKey,
) -> handshake_sync::Result<()> {
    let handshake = handshake_client(&socket, net_id, pk, sk, server_pk)?;
    println!("Handshake complete! 💃");
    debug!("{:#?}", handshake);
    print_shared_secret(&handshake.shared_secret);

    let (key_nonce_send, key_nonce_recv) = KeyNonce::from_handshake(handshake);
    let (mut box_stream_read, mut box_stream_write) =
        BoxStream::new(&socket, &socket, key_nonce_send, key_nonce_recv).split_read_write();

    thread::scope(|s| {
        let handle = s.spawn(move |_| io::copy(&mut box_stream_read, &mut io::stdout()).unwrap());
        io::copy(&mut io::stdin(), &mut box_stream_write).unwrap();
        handle.join().unwrap();
    })
    .unwrap();
    // box_stream.write(b"I'm the client")?;
    // box_stream.flush()?;
    // let mut buf = [0; 0x1000];
    // let n = box_stream.read(&mut buf)?;
    // println!("Received:");
    // io::stdout().write_all(&buf[..n])?;
    // println!();
    Ok(())
}

fn main() {
    env_logger::init();
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage(&args[0]);
        return;
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
                return;
            }
            let server_pk_buf = base64::decode_config(args[3].as_str(), base64::STANDARD).unwrap();
            let server_pk = ed25519::PublicKey::from_slice(&server_pk_buf).unwrap();
            let socket = TcpStream::connect(args[2].as_str()).unwrap();
            test_client(socket, net_id, pk, sk, server_pk).unwrap();
        }
        "server" => {
            if args.len() < 3 {
                usage(&args[0]);
                return;
            }
            let listener = TcpListener::bind(args[2].as_str()).unwrap();
            println!(
                "Listening for a handshake via TCP at {} ...",
                args[2].as_str()
            );
            let (socket, addr) = listener.accept().unwrap();
            println!("Client {} connected", addr);
            test_server(socket, net_id, pk, sk).unwrap();
        }
        _ => {}
    }
}
