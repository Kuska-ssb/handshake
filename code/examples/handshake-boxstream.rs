extern crate base64;
extern crate code;
extern crate crossbeam;

use crossbeam::thread;
use log::debug;
use sodiumoxide::crypto::{auth, sign::ed25519};
use std::env;
use std::io::{self};
use std::net::{TcpListener, TcpStream};

use code::boxstream::BoxStream;
use code::handshake::{handshake_client_sync, handshake_server_sync, Handshake, SharedSecret};

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

fn test_server(
    socket: TcpStream,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
) -> io::Result<()> {
    let handshake_complete = handshake_server_sync(&socket, net_id, pk, sk)?;
    println!("Handshake complete! 💃");
    println!("{:#?}", handshake_complete);
    print_shared_secret(&handshake_complete.shared_secret);

    let (read_buf, write_buf) = (&mut [0; 0x8000], &mut [0; 0x8000]);
    let (mut box_stream_read, mut box_stream_write) =
        BoxStream::new(&socket, &socket, read_buf, write_buf, handshake_complete)
            .unwrap()
            .split_read_write();

    thread::scope(|s| {
        let handle = s.spawn(move |_| io::copy(&mut box_stream_read, &mut io::stdout()).unwrap());
        io::copy(&mut io::stdin(), &mut box_stream_write);
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
) -> io::Result<()> {
    let handshake_complete = handshake_client_sync(&socket, net_id, pk, sk, server_pk)?;
    println!("Handshake complete! 💃");
    println!("{:#?}", handshake_complete);
    print_shared_secret(&handshake_complete.shared_secret);

    let (read_buf, write_buf) = (&mut [0; 0x8000], &mut [0; 0x8000]);
    let (mut box_stream_read, mut box_stream_write) =
        BoxStream::new(&socket, &socket, read_buf, write_buf, handshake_complete)
            .unwrap()
            .split_read_write();

    thread::scope(|s| {
        let handle = s.spawn(move |_| io::copy(&mut box_stream_read, &mut io::stdout()).unwrap());
        io::copy(&mut io::stdin(), &mut box_stream_write);
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

fn main() -> io::Result<()> {
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
            let socket = TcpStream::connect(args[2].as_str())?;
            test_client(socket, net_id, pk, sk, server_pk)
        }
        "server" => {
            if args.len() < 3 {
                usage(&args[0]);
                return Ok(());
            }
            let listener = TcpListener::bind(args[2].as_str()).unwrap();
            println!(
                "Listening for a handshake via TCP at {} ...",
                args[2].as_str()
            );
            let (socket, addr) = listener.accept()?;
            println!("Client {} connected", addr);
            test_server(socket, net_id, pk, sk)
        }
        _ => Ok(()),
    }
}
