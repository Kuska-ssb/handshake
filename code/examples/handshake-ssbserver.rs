extern crate base64;
extern crate code;
extern crate crossbeam;

use crossbeam::thread;
use log::debug;
use sodiumoxide::crypto::{auth, sign::ed25519};
use std::env;
use std::io::{self};
use std::net::{TcpListener, TcpStream};
use std::io::Read;

use code::handshake::{Handshake, SharedSecret};
use code::config::IdentitySecret;

fn usage(arg0: &str) {
    eprintln!(
        "Usage: {0} OPTS
         OPTS: addr",
        arg0
    );
}

enum RpcBodyType {
    Binary,
    UTF8,
    JSON,
}

const RPC_HEADER_STREAM_FLAG : u8 = 1 << 3;
const RPC_HEADER_END_OR_ERROR_FLAG : u8 = 1 << 2;
const RPC_HEADER_BODY_TYPE_MASK : u8 = 0b11;


fn test_server(
    socket: TcpStream,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
) -> io::Result<()> {
    let handshake = Handshake::new_server(&socket, &socket, net_id, pk, sk)
        .recv_client_hello()?
        .send_server_hello()?
        .recv_client_auth()?
        .send_server_accept()?;
    
    println!("Handshake complete! 💃");

    let (mut box_stream_read, mut box_stream_write) =
        handshake.to_box_stream(0x8000).split_read_write();

    // read rpc header
    let mut rpc_header = [0u8;9];
    box_stream_read.read(&mut rpc_header[..]).unwrap();

    let rpc_is_stream = rpc_header[0] & RPC_HEADER_STREAM_FLAG;
    let rpc_is_end_of_error = rpc_header[0] & RPC_HEADER_END_OR_ERROR_FLAG;
    let rpc_body_type = match rpc_header[0] & RPC_HEADER_BODY_TYPE_MASK {
        0 => RpcBodyType::Binary,
        1 => RpcBodyType::UTF8,
        2 => RpcBodyType::JSON,
        _ => unimplemented!(),
    };

    let mut rpc_msg_len_buff = [0u8;4];
    rpc_msg_len_buff.copy_from_slice(&rpc_header[1..5]);
    let rpc_msg_len = u32::from_be_bytes(rpc_msg_len_buff);

    let mut rpc_msg_reqno_buff = [0u8;4];
    rpc_msg_reqno_buff.copy_from_slice(&rpc_header[5..9]);
    let rpc_msg_reqno = u32::from_be_bytes(rpc_msg_reqno_buff);

    // read rpc body
    let mut rpc_body = Vec::with_capacity(rpc_msg_len as usize);
    rpc_body.resize(rpc_body.capacity(),0);
    box_stream_read.read(&mut rpc_body).unwrap();
    
    let rpc_str = String::from_utf8(rpc_body.to_vec()).unwrap();
    
    if rpc_str == r#"{"name":["whoami"],"args":[]}"#  {
        println!("yeah!");
    } else {
        println!("rpc_recieved: '{}'",rpc_str);
    }

    Ok(())
}

fn main() -> io::Result<()> {
    env_logger::init();
    log::set_max_level(log::LevelFilter::max());

    let args: Vec<String> = env::args().collect();
    if args.len() < 1 {
        usage(&args[0]);
        return Ok(());
    }
    let net_id_hex = "d4a1cb88a66f02f8db635ce26441cc5dac1b08420ceaac230839b755845a9ffb";
    let net_id = auth::Key::from_slice(&hex::decode(net_id_hex).unwrap()).unwrap();

    let local_key_file = format!("{}/.ssb/secret",
        dirs::home_dir().expect("cannot read home dir").to_string_lossy());

    let IdentitySecret{pk,sk,..} = std::fs::read_to_string(local_key_file)
        .and_then(IdentitySecret::from_config)
        .expect("Something went wrong reading the secret");

    let pk_b64 = base64::encode_config(&pk, base64::STANDARD);
    println!("Public key: {}", pk_b64);

    let listener = TcpListener::bind(args[1].as_str()).unwrap();
    println!(
        "Listening for a handshake via TCP at {} ...",
        args[1].as_str()
    );
    let (socket, addr) = listener.accept()?;
    println!("Client {} connected", addr);
    test_server(socket, net_id, pk, sk)
}
