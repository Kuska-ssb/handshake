extern crate sodiumoxide;

use std::{
    io,
    io::Result,
    io::Read,
    io::Write,
};
use sodiumoxide::crypto::{
    sign::ed25519,
    auth,
    hash::sha256,
    secretbox,
    scalarmult::curve25519,
};

#[derive(Debug)]
#[allow(non_snake_case)]
pub struct SharedSecret {
    ab: curve25519::GroupElement,
    aB: curve25519::GroupElement,
    Ab: curve25519::GroupElement,
}

#[derive(Debug)]
pub struct HandshakeBase<T> {
    stream: T,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
    ephemeral_pk: curve25519::GroupElement,
    ephemeral_sk: curve25519::Scalar,
}

#[derive(Debug)]
pub struct Handshake<T, S: State> {
    base: HandshakeBase<T>,
    state: S,
}

// Client States
#[derive(Debug)]
struct SendClientHello;

#[derive(Debug)]
struct RecvServerHello;

#[derive(Debug)]
struct SendClientAuth{
    server_pk: ed25519::PublicKey,
    server_ephemeral_pk: curve25519::GroupElement,
    shared_secret: SharedSecret,
}

#[derive(Debug)]
struct RecvServerAccept{
    server_pk: ed25519::PublicKey,
    server_ephemeral_pk: curve25519::GroupElement,
    shared_secret: SharedSecret,
    sig: ed25519::Signature,
}

// Server States
#[derive(Debug)]
struct RecvClientHello;

#[derive(Debug)]
#[allow(non_snake_case)]
struct SendServerHello{
    client_ephemeral_pk: curve25519::GroupElement,
    shared_secret_ab: curve25519::GroupElement,
    shared_secret_aB: curve25519::GroupElement,
}

#[derive(Debug)]
#[allow(non_snake_case)]
struct RecvClientAuth{
    client_ephemeral_pk: curve25519::GroupElement,
    shared_secret_ab: curve25519::GroupElement,
    shared_secret_aB: curve25519::GroupElement,
}

#[derive(Debug)]
#[allow(non_snake_case)]
struct SendServerAccept{
    client_pk: ed25519::PublicKey,
    client_ephemeral_pk: curve25519::GroupElement,
    shared_secret: SharedSecret,
    client_sig: ed25519::Signature,
}

// Shared States
#[derive(Debug)]
struct Complete{
    peer_pk: ed25519::PublicKey,
    peer_ephemeral_pk: curve25519::GroupElement,
    shared_secret: SharedSecret,
}

pub trait State {}
impl State for SendClientHello {}
impl State for RecvServerHello {}
impl State for SendClientAuth {}
impl State for RecvServerAccept {}

impl State for RecvClientHello {}
impl State for SendServerHello {}
impl State for RecvClientAuth {}
impl State for SendServerAccept {}

impl State for Complete {}

fn error_new(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, msg)
}

// Client
impl<T> Handshake<T, SendClientHello> {
    fn new_client(
        stream: T,
        net_id: auth::Key,
        pk: ed25519::PublicKey,
        sk: ed25519::SecretKey) -> Handshake<T, SendClientHello> {
        let (ephemeral_ed_pk, ephemeral_ed_sk) = ed25519::gen_keypair();
        let ephemeral_pk = ephemeral_ed_pk.to_curve25519();
        let ephemeral_sk = ephemeral_ed_sk.to_curve25519();
        let state = SendClientHello;
        let base = HandshakeBase{ stream, net_id, pk, sk, ephemeral_pk, ephemeral_sk };
        Handshake{ base, state }
    }
}

impl<T: Write> Handshake<T, SendClientHello> {
    fn send_client_hello(mut self) -> Result<Handshake<T, RecvServerHello>> {
        let send = [
            auth::authenticate(self.base.ephemeral_pk.as_ref(), &self.base.net_id).as_ref(),
            self.base.ephemeral_pk.as_ref(),
        ].concat();
        self.base.stream.write_all(&send)?;
        self.base.stream.flush()?;
        let state = RecvServerHello;
        Ok(Handshake{ base: self.base, state })
    }
}

impl<T: Read> Handshake<T, RecvServerHello> {
    fn recv_server_hello(
        mut self,
        server_pk: ed25519::PublicKey) -> Result<Handshake<T, SendClientAuth>> {
        let mut recv = [0; 64];
        self.base.stream.read_exact(&mut recv)?;
        let server_hmac = auth::Tag::from_slice(&recv[..32]).unwrap();
        let server_ephemeral_pk = curve25519::GroupElement::from_slice(&recv[32..]).unwrap();
        if !auth::verify(&server_hmac, server_ephemeral_pk.as_ref(), &self.base.net_id) {
            return Err(error_new("auth::verify failed in recv_server_hello"));
        }
        let fn_error = |a, b| Err(error_new(
                &format!("curve25519::scalarmult({}, {}) failed in recv_server_hello", a, b)));
        let shared_secret = SharedSecret{
            ab: curve25519::scalarmult(
                &self.base.ephemeral_sk,
                &server_ephemeral_pk).or(fn_error("ephemeral_sk", "server_ephemeral_pk"))?,
            aB: curve25519::scalarmult(
                &self.base.ephemeral_sk,
                &server_pk.to_curve25519()).or(fn_error("ephemeral_sk", "server_pk"))?,
            Ab: curve25519::scalarmult(
                &self.base.sk.to_curve25519(),
                &server_ephemeral_pk).or(fn_error("sk", "server_ephemeral_pk"))?,
        };
        let state = SendClientAuth{ server_pk, server_ephemeral_pk, shared_secret };
        Ok(Handshake{ base: self.base, state })
    }
}

impl<T: Write> Handshake<T, SendClientAuth> {
    fn send_client_auth(mut self) -> Result<Handshake<T, RecvServerAccept>> {
        let sig = ed25519::sign_detached(
            &[
                self.base.net_id.as_ref(),
                self.state.server_pk.as_ref(),
                sha256::hash(self.state.shared_secret.ab.as_ref()).as_ref(),
            ].concat(),
            &self.base.sk,
        );
        let send = secretbox::seal(
            &[
                sig.as_ref(),
                self.base.pk.as_ref(),
            ].concat(),
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(sha256::hash(
                &[
                    self.base.net_id.as_ref(),
                    self.state.shared_secret.ab.as_ref(),
                    self.state.shared_secret.aB.as_ref(),
                ].concat()
            ).0),
        );
        self.base.stream.write_all(&send)?;
        self.base.stream.flush()?;
        let state = RecvServerAccept{
            server_pk: self.state.server_pk,
            server_ephemeral_pk: self.state.server_ephemeral_pk,
            shared_secret: self.state.shared_secret,
            sig
        };
        Ok(Handshake{ base: self.base, state })
    }
}

impl<T: Read> Handshake<T, RecvServerAccept> {
    fn recv_server_accept(mut self) -> Result<Handshake<T, Complete>> {
        let mut recv_enc = [0; 80];
        self.base.stream.read_exact(&mut recv_enc)?;
        let recv = secretbox::open(
            &recv_enc,
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(sha256::hash(
                &[
                    self.base.net_id.as_ref(),
                    self.state.shared_secret.ab.as_ref(),
                    self.state.shared_secret.aB.as_ref(),
                    self.state.shared_secret.Ab.as_ref(),
                ].concat()
            ).0),
        ).or(Err(error_new("secretbox::open failed in recv_server_accept")))?;
        let sig = ed25519::Signature::from_slice(&recv[..64]).unwrap();
        if !ed25519::verify_detached(
            &sig,
            &[
                self.base.net_id.as_ref(),
                self.state.sig.as_ref(),
                self.base.pk.as_ref(),
                sha256::hash(self.state.shared_secret.ab.as_ref()).as_ref(),
            ].concat(),
            &self.state.server_pk,
        ) {
            return Err(error_new("ed25519::verify_detached failed in recv_server_accept"));
        }
        let state = Complete{
            peer_pk: self.state.server_pk,
            peer_ephemeral_pk: self.state.server_ephemeral_pk,
            shared_secret: self.state.shared_secret,
        };
        Ok(Handshake{ base: self.base, state})
    }
}

// Server
impl<T> Handshake<T, RecvClientHello> {
    fn new_server(
        stream: T,
        net_id: auth::Key,
        pk: ed25519::PublicKey,
        sk: ed25519::SecretKey) -> Handshake<T, RecvClientHello> {
        let (ephemeral_ed_pk, ephemeral_ed_sk) = ed25519::gen_keypair();
        let ephemeral_pk = ephemeral_ed_pk.to_curve25519();
        let ephemeral_sk = ephemeral_ed_sk.to_curve25519();
        let state = RecvClientHello;

        let base = HandshakeBase{ stream, net_id, pk, sk, ephemeral_pk, ephemeral_sk };
        Handshake{ base, state }
    }
}

impl<T: Read> Handshake<T, RecvClientHello> {
    fn recv_client_hello(mut self) -> Result<Handshake<T, SendServerHello>> {
        let mut recv = [0; 64];
        self.base.stream.read_exact(&mut recv)?;
        let client_hmac = auth::Tag::from_slice(&recv[..32]).unwrap();
        let client_ephemeral_pk = curve25519::GroupElement::from_slice(&recv[32..]).unwrap();
        if !auth::verify(&client_hmac, client_ephemeral_pk.as_ref(), &self.base.net_id) {
            return Err(error_new("auth::verify failed in recv_client_hello"));
        }
        let fn_error = |a, b| Err(error_new(
                &format!("curve25519::scalarmult({}, {}) failed in recv_client_hello", a, b)));
        #[allow(non_snake_case)]
        let shared_secret_ab = curve25519::scalarmult(
            &self.base.ephemeral_sk,
            &client_ephemeral_pk).or(fn_error("ephemeral_sk", "client_ephemeral_pk"))?;
        #[allow(non_snake_case)]
        let shared_secret_aB = curve25519::scalarmult(
            &self.base.sk.to_curve25519(),
            &client_ephemeral_pk).or(fn_error("sk", "client_ephemeral_pk"))?;
        let state = SendServerHello{
            client_ephemeral_pk,
            shared_secret_ab,
            shared_secret_aB,
        };
        Ok(Handshake{base: self.base, state: state})
    }
}

impl<T: Write> Handshake<T, SendServerHello> {
    fn send_server_hello(mut self) -> Result<Handshake<T, RecvClientAuth>> {
        let send = [
            auth::authenticate(self.base.ephemeral_pk.as_ref(), &self.base.net_id).as_ref(),
            self.base.ephemeral_pk.as_ref(),
        ].concat();
        self.base.stream.write_all(&send)?;
        self.base.stream.flush()?;
        let state = RecvClientAuth{
            client_ephemeral_pk: self.state.client_ephemeral_pk,
            shared_secret_ab: self.state.shared_secret_ab,
            shared_secret_aB: self.state.shared_secret_aB,
        };
        Ok(Handshake{ base: self.base, state })
    }
}

impl<T: Read> Handshake<T, RecvClientAuth> {
    fn recv_client_auth(mut self) -> Result<Handshake<T, SendServerAccept>> {
        let mut recv_enc = [0; 112];
        self.base.stream.read_exact(&mut recv_enc)?;
        let recv = secretbox::open(
            &recv_enc,
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(sha256::hash(
                &[
                    self.base.net_id.as_ref(),
                    self.state.shared_secret_ab.as_ref(),
                    self.state.shared_secret_aB.as_ref(),
                ].concat()
            ).0),
        ).or(Err(error_new("secretbox::open failed in recv_client_auth")))?;
        let client_sig = ed25519::Signature::from_slice(&recv[..64]).unwrap();
        let client_pk = ed25519::PublicKey::from_slice(&recv[64..]).unwrap();
        if !ed25519::verify_detached(
            &client_sig,
            &[
                self.base.net_id.as_ref(),
                self.base.pk.as_ref(),
                sha256::hash(self.state.shared_secret_ab.as_ref()).as_ref(),
            ].concat(),
            &client_pk,
        ) {
            return Err(error_new("ed25519::verify_detached failed in recv_client_auth"));
        }
        let fn_error = |a, b| Err(error_new(
                &format!("curve25519::scalarmult({}, {}) failed in recv_client_auth", a, b)));
        #[allow(non_snake_case)]
        let shared_secret_Ab = curve25519::scalarmult(
                &self.base.ephemeral_sk,
                &client_pk.to_curve25519()).or(fn_error("ephemeral_sk", "client_pk"))?;
        let state = SendServerAccept{
            client_pk,
            client_ephemeral_pk: self.state.client_ephemeral_pk,
            shared_secret: SharedSecret{
                ab: self.state.shared_secret_ab,
                aB: self.state.shared_secret_aB,
                Ab: shared_secret_Ab,
            },
            client_sig,
        };
        Ok(Handshake{ base: self.base, state })
    }
}

impl<T: Write> Handshake<T, SendServerAccept> {
    fn send_server_accept(mut self) -> Result<Handshake<T, Complete>> {
        let sig = ed25519::sign_detached(
            &[
                self.base.net_id.as_ref(),
                self.state.client_sig.as_ref(),
                self.state.client_pk.as_ref(),
                sha256::hash(self.state.shared_secret.ab.as_ref()).as_ref(),
            ].concat(),
            &self.base.sk,
        );
        let send = secretbox::seal(
            sig.as_ref(),
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(sha256::hash(
                &[
                    self.base.net_id.as_ref(),
                    self.state.shared_secret.ab.as_ref(),
                    self.state.shared_secret.aB.as_ref(),
                    self.state.shared_secret.Ab.as_ref(),
                ].concat()
            ).0),
        );
        self.base.stream.write_all(&send)?;
        self.base.stream.flush()?;
        let state = Complete{
            peer_pk: self.state.client_pk,
            peer_ephemeral_pk: self.state.client_ephemeral_pk,
            shared_secret: self.state.shared_secret,
        };
        Ok(Handshake{ base: self.base, state })
    }
}

extern crate base64;

use std::env;
use std::net::{TcpListener, TcpStream};

fn usage(arg0: &str) {
    eprintln!("Usage: {0} [client/server] OPTS
    client OPTS: server_pk addr
    server OPTS: addr", arg0);
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
    sk: ed25519::SecretKey) -> io::Result<()> {
    let handshake = Handshake::new_server(socket, net_id, pk, sk).
        recv_client_hello()?.
        send_server_hello()?.
        recv_client_auth()?.
        send_server_accept()?;
    println!("Handshake complete!");
    println!("{:#?}", handshake);
    print_shared_secret(&handshake.state.shared_secret);
    Ok(())
}

fn test_client(
    socket: TcpStream,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
    server_pk: ed25519::PublicKey) -> io::Result<()> {
    let handshake = Handshake::new_client(socket, net_id, pk, sk).
        send_client_hello()?.
        recv_server_hello(server_pk)?.
        send_client_auth()?.
        recv_server_accept()?;
    println!("Handshake complete!");
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
            let server_pk_buf = base64::decode_config(args[2].as_str(), base64::STANDARD).unwrap();
            let server_pk = ed25519::PublicKey::from_slice(&server_pk_buf).unwrap();
            let socket = TcpStream::connect(args[3].as_str())?;
            test_client(socket, net_id, pk, sk, server_pk)
        },
        "server" => {
            if args.len() < 3 {
                usage(&args[0]);
                return Ok(());
            }
            let listener = TcpListener::bind(args[2].as_str()).unwrap();
            println!("Listening for a handshake via TCP at {} ...", args[2].as_str());
            let (socket, addr) = listener.accept()?;
            println!("Client {} connected", addr);
            test_server(socket, net_id, pk, sk)
        },
        _ => Ok(()),
    }
}
