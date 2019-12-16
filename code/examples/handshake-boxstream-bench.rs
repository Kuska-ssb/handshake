extern crate base64;
extern crate code;

use std::env;
use std::io::{self};
use std::net::{TcpListener, TcpStream};

use sodiumoxide::crypto::{auth, sign::ed25519};

use code::boxstream::KeyNonce;
use code::boxstream_sync::BoxStream;
use code::handshake_sync::{handshake_client, handshake_server};

const BUF_SIZE: usize = 0x8000;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} [client/server] address [--buf]", args[0]);
        return;
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
            let socket = TcpStream::connect(addr).unwrap();

            let handshake =
                handshake_client(&socket, net_id, client_pk, client_sk, server_pk).unwrap();
            (handshake, socket)
        }
        "server" => {
            let listener = TcpListener::bind(addr).unwrap();
            let (socket, _) = listener.accept().unwrap();

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
        BoxStream::new(&socket, &socket, key_nonce_send, key_nonce_recv).split_read_write();

    match mode {
        "client" => {
            // stdin -> boxstream
            if buffered {
                io::copy(
                    &mut io::BufReader::with_capacity(BUF_SIZE, &mut io::stdin()),
                    &mut io::BufWriter::with_capacity(BUF_SIZE, &mut box_stream_write),
                )
                .unwrap();
            } else {
                io::copy(&mut io::stdin(), &mut box_stream_write).unwrap();
            }
        }
        "server" => {
            // boxstream -> stdout
            if buffered {
                io::copy(
                    &mut io::BufReader::with_capacity(BUF_SIZE, &mut box_stream_read),
                    &mut io::BufWriter::with_capacity(BUF_SIZE, &mut io::stdout()),
                )
                .unwrap();
            } else {
                io::copy(&mut box_stream_read, &mut io::stdout()).unwrap();
            }
        }
        _ => unreachable!(),
    }
}

// Copied from https://doc.rust-lang.org/src/std/io/util.rs.html#43 to be used with custom buffer
// size.
pub fn copy<R: ?Sized, W: ?Sized>(reader: &mut R, writer: &mut W) -> io::Result<u64>
where
    R: io::Read,
    W: io::Write,
{
    let mut buf = [0; BUF_SIZE];

    let mut written = 0;
    loop {
        let len = match reader.read(&mut buf) {
            Ok(0) => return Ok(written),
            Ok(len) => len,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        writer.write_all(&buf[..len])?;
        written += len as u64;
    }
}
