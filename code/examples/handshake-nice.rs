extern crate base64;
extern crate code;

use sodiumoxide::crypto::{auth, sign::ed25519};
use std::env;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};

use code::handshake::{Handshake, SharedSecret, CLIENT_HELLO_BYTES, CLIENT_AUTH_BYTES, SERVER_HELLO_BYTES, SERVER_ACCEPT_BYTES};

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
    mut socket: TcpStream,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
) -> io::Result<()> {
    let handshake = Handshake::new_server(net_id, pk, sk);
    let handshake = {
        let mut recv_buf = [0; CLIENT_HELLO_BYTES];
        socket.read_exact(&mut recv_buf)?;
        handshake.recv_client_hello(&mut recv_buf)?
    };
    let handshake = {
        let mut send_buf = [0; SERVER_HELLO_BYTES];
        let handshake = handshake.send_server_hello(&mut send_buf)?;
        socket.write_all(&mut send_buf)?;
        handshake
    };
    let handshake = {
        let mut recv_buf = [0; CLIENT_AUTH_BYTES];
        socket.read_exact(&mut recv_buf)?;
        handshake.recv_client_auth(&mut recv_buf)?
    };
    let handshake = {
        let mut send_buf = [0; SERVER_ACCEPT_BYTES];
        let handshake = handshake.send_server_accept(&mut send_buf)?;
        socket.write_all(&mut send_buf)?;
        handshake
    };
    println!("Handshake complete! 💃");
    println!("{:#?}", handshake);
    print_shared_secret(&handshake.state.shared_secret);
    Ok(())
}

fn test_client(
    mut socket: TcpStream,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
    server_pk: ed25519::PublicKey,
) -> io::Result<()> {
    let handshake = Handshake::new_client(net_id, pk, sk);
    let handshake = {
        let mut send_buf = [0; CLIENT_HELLO_BYTES];
        let handshake = handshake.send_client_hello(&mut send_buf)?;
        socket.write_all(&send_buf)?;
        handshake
    };
    let handshake = {
        let mut recv_buf = [0; SERVER_HELLO_BYTES];
        socket.read_exact(&mut recv_buf)?;
        handshake.recv_server_hello(&recv_buf)?
    };
    let handshake = {
        let mut send_buf = [0; CLIENT_AUTH_BYTES];
        let handshake = handshake.send_client_auth(&mut send_buf, server_pk)?;
        socket.write_all(&send_buf)?;
        handshake
    };
    let handshake = {
        let mut recv_buf = [0; SERVER_ACCEPT_BYTES];
        socket.read_exact(&mut recv_buf)?;
        handshake.recv_server_accept(&recv_buf)?
    };
    println!("Handshake complete! 💃");
    println!("{:#?}", handshake);
    print_shared_secret(&handshake.state.shared_secret);
    Ok(())
}

fn main() -> io::Result<()> {
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
