extern crate base64;
extern crate code;
extern crate crossbeam;

use sodiumoxide::crypto::{auth, sign::ed25519};
use std::io::{self};
use std::net::{TcpStream};

use code::handshake::Handshake;
use code::config::{IdentitySecret,ssb_net_id};
use code::rpc;

fn test_client(
    socket: TcpStream,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
    server_pk: ed25519::PublicKey,
) -> io::Result<()> {

    let handshake = Handshake::new_client(&socket, &socket, net_id, pk, sk)
        .send_client_hello()?
        .recv_server_hello()?
        .send_client_auth(server_pk)?
        .recv_server_accept()?;

    let (box_stream_read, box_stream_write) =
        handshake.to_box_stream(0x8000).split_read_write();

    let mut client = rpc::Client::new(box_stream_read, box_stream_write);
    let req_no = client.send_whoami()?;

    let mut whoami = None;
    while whoami.is_none() {
        let (header,body) = client.recv()?;
        if header.req_no == -req_no {
            whoami = Some(rpc::parse_error::<rpc::WhoAmI>(&(header,body))?) 
        }
    }
    
    println!("{}: {}",req_no,whoami.unwrap().id);
    Ok(())
}

fn main() -> io::Result<()> {

    env_logger::init();
    log::set_max_level(log::LevelFilter::max());

    let IdentitySecret{pk,sk,..} = IdentitySecret::from_local_config()
        .expect("read local secret");

    let socket = TcpStream::connect("127.0.0.1:8008")?;
    test_client(socket, ssb_net_id(), pk, sk, pk)?;

    Ok(())
}