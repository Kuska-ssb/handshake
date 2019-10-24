extern crate sodiumoxide;

use crate::boxstream::BoxStream;

use sodiumoxide::crypto::{auth, hash::sha256, scalarmult::curve25519, secretbox, sign::ed25519};
use std::{io, io::Read, io::Result, io::Write};

#[derive(Debug)]
#[allow(non_snake_case)]
pub struct SharedSecretPartial {
    ab: curve25519::GroupElement,
    aB: curve25519::GroupElement,
}

#[derive(Debug, Clone)]
#[allow(non_snake_case)]
pub struct SharedSecret {
    pub ab: curve25519::GroupElement,
    pub aB: curve25519::GroupElement,
    pub Ab: curve25519::GroupElement,
}

#[derive(Debug)]
pub struct HandshakeBase {
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
    ephemeral_pk: curve25519::GroupElement,
    ephemeral_sk: curve25519::Scalar,
}

#[derive(Debug)]
pub struct Handshake<S: State> {
    pub base: HandshakeBase,
    pub state: S,
}

// Client States
#[derive(Debug)]
pub struct SendClientHello;

#[derive(Debug)]
pub struct RecvServerHello;

#[derive(Debug)]
pub struct SendClientAuth {
    server_ephemeral_pk: curve25519::GroupElement,
}

#[derive(Debug)]
pub struct RecvServerAccept {
    server_pk: ed25519::PublicKey,
    server_ephemeral_pk: curve25519::GroupElement,
    shared_secret: SharedSecret,
    sig: ed25519::Signature,
}

// Server States
#[derive(Debug)]
pub struct RecvClientHello;

#[derive(Debug)]
pub struct SendServerHello {
    client_ephemeral_pk: curve25519::GroupElement,
    shared_secret_partial: SharedSecretPartial,
}

#[derive(Debug)]
pub struct RecvClientAuth {
    client_ephemeral_pk: curve25519::GroupElement,
    shared_secret_partial: SharedSecretPartial,
}

#[derive(Debug)]
#[allow(non_snake_case)]
pub struct SendServerAccept {
    client_pk: ed25519::PublicKey,
    client_ephemeral_pk: curve25519::GroupElement,
    shared_secret: SharedSecret,
    client_sig: ed25519::Signature,
}

// Shared States
#[derive(Debug)]
pub struct Complete {
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

fn scalarmult_error_new(fn_name: &str, a: &str, b: &str) -> io::Error {
    error_new(&format!(
        "curve25519::scalarmult({}, {}) failed in {}",
        a, b, fn_name
    ))
}

// Helper struct to easilly append u8 slices into another slice
struct Buffer<'a> {
    buf: &'a mut [u8],
    n: usize,
}

macro_rules! concat_into {
    ( $dst:expr, $( $x:expr ),* ) => {
        {
            let mut n = 0;
            $(
                n += $x.len();
                $dst[n - $x.len()..n].copy_from_slice($x);
            )*
            $dst
        }
    };
}

macro_rules! concat {
    ( $n:expr, $( $x:expr ),* ) => {
        {
            let mut dst = [0; $n];
            concat_into!(dst, $( $x ),*);
            dst
        }
    };
}

impl<'a> Buffer<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Buffer{ buf: buf, n: 0 }
    }
    fn append(&mut self, src: &[u8]) {
        self.buf[self.n..src.len()].copy_from_slice(src);
        self.n += src.len();
    }
}

// Client
impl Handshake<SendClientHello> {
    pub fn new_client(
        net_id: auth::Key,
        pk: ed25519::PublicKey,
        sk: ed25519::SecretKey,
    ) -> Handshake<SendClientHello> {
        let (ephemeral_ed_pk, ephemeral_ed_sk) = ed25519::gen_keypair();
        let ephemeral_pk = ephemeral_ed_pk.to_curve25519();
        let ephemeral_sk = ephemeral_ed_sk.to_curve25519();
        let state = SendClientHello;
        let base = HandshakeBase {
            net_id,
            pk,
            sk,
            ephemeral_pk,
            ephemeral_sk,
        };
        Handshake { base, state }
    }
}

pub const CLIENT_HELLO_BYTES: usize = 64;

impl Handshake<SendClientHello> {
    pub fn send_client_hello(self, send_buf: &mut [u8]) -> Result<Handshake<RecvServerHello>> {
        concat_into!(send_buf,
            auth::authenticate(self.base.ephemeral_pk.as_ref(), &self.base.net_id).as_ref(),
            self.base.ephemeral_pk.as_ref());
        let state = RecvServerHello;
        Ok(Handshake {
            base: self.base,
            state,
        })
    }
}

impl Handshake<RecvServerHello> {
    pub fn recv_server_hello(self, recv_buf: &[u8]) -> Result<Handshake<SendClientAuth>> {
        let server_hmac = auth::Tag::from_slice(&recv_buf[..32]).unwrap();
        let server_ephemeral_pk = curve25519::GroupElement::from_slice(&recv_buf[32..]).unwrap();
        if !auth::verify(
            &server_hmac,
            server_ephemeral_pk.as_ref(),
            &self.base.net_id,
        ) {
            return Err(error_new("auth::verify failed in recv_server_hello"));
        }
        Ok(Handshake {
            base: self.base,
            state: SendClientAuth {
                server_ephemeral_pk,
            },
        })
    }
}

pub const CLIENT_AUTH_BYTES: usize = 112;

impl Handshake<SendClientAuth> {
    pub fn send_client_auth(
        self,
        send_buf: &mut [u8],
        server_pk: ed25519::PublicKey,
    ) -> Result<Handshake<RecvServerAccept>> {
        let fn_error = |a, b| Err(scalarmult_error_new("send_client_auth", a, b));
        let shared_secret = SharedSecret {
            ab: curve25519::scalarmult(&self.base.ephemeral_sk, &self.state.server_ephemeral_pk)
                .or(fn_error("ephemeral_sk", "server_ephemeral_pk"))?,
            aB: curve25519::scalarmult(&self.base.ephemeral_sk, &server_pk.to_curve25519())
                .or(fn_error("ephemeral_sk", "server_pk"))?,
            Ab: curve25519::scalarmult(
                &self.base.sk.to_curve25519(),
                &self.state.server_ephemeral_pk,
            )
            .or(fn_error("sk", "server_ephemeral_pk"))?,
        };

        let sig = ed25519::sign_detached(
            &concat!(
                auth::KEYBYTES + ed25519::PUBLICKEYBYTES + sha256::DIGESTBYTES,
                self.base.net_id.as_ref(),
                server_pk.as_ref(),
                sha256::hash(shared_secret.ab.as_ref()).as_ref()
            ),
            &self.base.sk);

        let tag = secretbox::seal_detached(
            concat_into!(&mut send_buf[secretbox::MACBYTES..], sig.as_ref(), self.base.pk.as_ref()),
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(sha256::hash(
                    &concat!(
                        auth::KEYBYTES + curve25519::GROUPELEMENTBYTES * 2,
                        self.base.net_id.as_ref(),
                        shared_secret.ab.as_ref(),
                        shared_secret.aB.as_ref()
        )).0));
        send_buf[..secretbox::MACBYTES].copy_from_slice(tag.as_ref());

        Ok(Handshake {
            base: self.base,
            state: RecvServerAccept {
                server_pk: server_pk,
                server_ephemeral_pk: self.state.server_ephemeral_pk,
                shared_secret: shared_secret,
                sig,
            },
        })
    }
}

impl Handshake<RecvServerAccept> {
    pub fn recv_server_accept(self, recv_buf: &[u8]) -> Result<Handshake<Complete>> {
        let recv = secretbox::open(
            &recv_buf,
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(
                sha256::hash(
                    &[
                        self.base.net_id.as_ref(),
                        self.state.shared_secret.ab.as_ref(),
                        self.state.shared_secret.aB.as_ref(),
                        self.state.shared_secret.Ab.as_ref(),
                    ]
                    .concat(),
                )
                .0,
            ),
        )
        .or(Err(error_new(
            "secretbox::open failed in recv_server_accept",
        )))?;
        let sig = ed25519::Signature::from_slice(&recv[..64]).unwrap();
        if !ed25519::verify_detached(
            &sig,
            &[
                self.base.net_id.as_ref(),
                self.state.sig.as_ref(),
                self.base.pk.as_ref(),
                sha256::hash(self.state.shared_secret.ab.as_ref()).as_ref(),
            ]
            .concat(),
            &self.state.server_pk,
        ) {
            return Err(error_new(
                "ed25519::verify_detached failed in recv_server_accept",
            ));
        }
        Ok(Handshake {
            base: self.base,
            state: Complete {
                peer_pk: self.state.server_pk,
                peer_ephemeral_pk: self.state.server_ephemeral_pk,
                shared_secret: self.state.shared_secret,
            },
        })
    }
}

// Server
impl Handshake<RecvClientHello> {
    pub fn new_server(
        net_id: auth::Key,
        pk: ed25519::PublicKey,
        sk: ed25519::SecretKey,
    ) -> Handshake<RecvClientHello> {
        let (ephemeral_ed_pk, ephemeral_ed_sk) = ed25519::gen_keypair();
        let ephemeral_pk = ephemeral_ed_pk.to_curve25519();
        let ephemeral_sk = ephemeral_ed_sk.to_curve25519();
        Handshake {
            base: HandshakeBase {
                net_id,
                pk,
                sk,
                ephemeral_pk,
                ephemeral_sk,
            },
            state: RecvClientHello,
        }
    }
}

impl Handshake<RecvClientHello> {
    pub fn recv_client_hello(self, recv_buf: &[u8]) -> Result<Handshake<SendServerHello>> {
        let client_hmac = auth::Tag::from_slice(&recv_buf[..32]).unwrap();
        let client_ephemeral_pk = curve25519::GroupElement::from_slice(&recv_buf[32..]).unwrap();
        if !auth::verify(
            &client_hmac,
            client_ephemeral_pk.as_ref(),
            &self.base.net_id,
        ) {
            return Err(error_new("auth::verify failed in recv_client_hello"));
        }
        let fn_error = |a, b| Err(scalarmult_error_new("recv_client_hello", a, b));
        let shared_secret_partial = SharedSecretPartial {
            ab: curve25519::scalarmult(&self.base.ephemeral_sk, &client_ephemeral_pk)
                .or(fn_error("ephemeral_sk", "client_ephemeral_pk"))?,
            aB: curve25519::scalarmult(&self.base.sk.to_curve25519(), &client_ephemeral_pk)
                .or(fn_error("sk", "client_ephemeral_pk"))?,
        };
        Ok(Handshake {
            base: self.base,
            state: SendServerHello {
                client_ephemeral_pk,
                shared_secret_partial,
            },
        })
    }
}

pub const SERVER_HELLO_BYTES: usize = 64;

impl Handshake<SendServerHello> {
    pub fn send_server_hello(self, send_buf: &mut [u8]) -> Result<Handshake<RecvClientAuth>> {
        concat_into!(send_buf,
            auth::authenticate(self.base.ephemeral_pk.as_ref(), &self.base.net_id).as_ref(),
            self.base.ephemeral_pk.as_ref());
        Ok(Handshake {
            base: self.base,
            state: RecvClientAuth {
                client_ephemeral_pk: self.state.client_ephemeral_pk,
                shared_secret_partial: self.state.shared_secret_partial,
            },
        })
    }
}

impl Handshake<RecvClientAuth> {
    pub fn recv_client_auth(self, recv_buf: &[u8]) -> Result<Handshake<SendServerAccept>> {
        let recv = secretbox::open(
            &recv_buf,
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(
                sha256::hash(
                    &[
                        self.base.net_id.as_ref(),
                        self.state.shared_secret_partial.ab.as_ref(),
                        self.state.shared_secret_partial.aB.as_ref(),
                    ]
                    .concat(),
                )
                .0,
            ),
        )
        .or(Err(error_new("secretbox::open failed in recv_client_auth")))?;
        let client_sig = ed25519::Signature::from_slice(&recv[..64]).unwrap();
        let client_pk = ed25519::PublicKey::from_slice(&recv[64..]).unwrap();
        if !ed25519::verify_detached(
            &client_sig,
            &[
                self.base.net_id.as_ref(),
                self.base.pk.as_ref(),
                sha256::hash(self.state.shared_secret_partial.ab.as_ref()).as_ref(),
            ]
            .concat(),
            &client_pk,
        ) {
            return Err(error_new(
                "ed25519::verify_detached failed in recv_client_auth",
            ));
        }
        let fn_error = |a, b| Err(scalarmult_error_new("recv_client_auth", a, b));
        let shared_secret = SharedSecret {
            ab: self.state.shared_secret_partial.ab,
            aB: self.state.shared_secret_partial.aB,
            Ab: curve25519::scalarmult(&self.base.ephemeral_sk, &client_pk.to_curve25519())
                .or(fn_error("ephemeral_sk", "client_pk"))?,
        };
        Ok(Handshake {
            base: self.base,
            state: SendServerAccept {
                client_pk,
                client_ephemeral_pk: self.state.client_ephemeral_pk,
                shared_secret,
                client_sig,
            },
        })
    }
}

pub const SERVER_ACCEPT_BYTES: usize = 80;

impl Handshake<SendServerAccept> {
    pub fn send_server_accept(self, send_buf: &mut [u8]) -> Result<Handshake<Complete>> {
        let sig = ed25519::sign_detached(
            &concat!(
                auth::KEYBYTES + ed25519::SIGNATUREBYTES + ed25519::PUBLICKEYBYTES + sha256::DIGESTBYTES,
                self.base.net_id.as_ref(),
                self.state.client_sig.as_ref(),
                self.state.client_pk.as_ref(),
                sha256::hash(self.state.shared_secret.ab.as_ref()).as_ref()
            ),
            &self.base.sk,
        );
        send_buf[secretbox::MACBYTES..].copy_from_slice(sig.as_ref());
        let tag = secretbox::seal_detached(
            &mut send_buf[secretbox::MACBYTES..],
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(
                sha256::hash(
                    &concat!(
                        auth::KEYBYTES + curve25519::GROUPELEMENTBYTES * 3,
                        self.base.net_id.as_ref(),
                        self.state.shared_secret.ab.as_ref(),
                        self.state.shared_secret.aB.as_ref(),
                        self.state.shared_secret.Ab.as_ref()
                    )
                )
                .0,
            ),
        );
        send_buf[..secretbox::MACBYTES].copy_from_slice(tag.as_ref());

        Ok(Handshake {
            base: self.base,
            state: Complete {
                peer_pk: self.state.client_pk,
                peer_ephemeral_pk: self.state.client_ephemeral_pk,
                shared_secret: self.state.shared_secret,
            },
        })
    }
}

#[derive(Debug)]
pub struct HandshakeComplete {
    pub net_id: auth::Key,
    pub pk: ed25519::PublicKey,
    pub ephemeral_pk: curve25519::GroupElement,
    pub peer_pk: ed25519::PublicKey,
    pub peer_ephemeral_pk: curve25519::GroupElement,
    pub shared_secret: SharedSecret,
}

impl Handshake<Complete> {
//     pub fn to_box_stream(self, recv_buf_len: usize) -> BoxStream<R, W> {
//         BoxStream::new(
//             self.base.read_stream,
//             self.base.write_stream,
//             recv_buf_len,
//             self.base.net_id,
//             self.base.pk,
//             self.base.ephemeral_pk,
//             self.state.peer_pk,
//             self.state.peer_ephemeral_pk,
//             self.state.shared_secret,
//         )
//     }
    pub fn complete(&self) -> HandshakeComplete {
        HandshakeComplete{
            net_id: self.base.net_id.clone(),
            pk: self.base.pk.clone(),
            ephemeral_pk: self.base.ephemeral_pk.clone(),
            peer_pk: self.state.peer_pk.clone(),
            peer_ephemeral_pk: self.state.peer_ephemeral_pk.clone(),
            shared_secret: self.state.shared_secret.clone(),
        }
    }
}

pub fn handshake_client_sync<T: Read + Write> (
        mut stream: T,
        net_id: auth::Key,
        pk: ed25519::PublicKey,
        sk: ed25519::SecretKey,
        server_pk: ed25519::PublicKey
    ) -> Result<HandshakeComplete> {
    let handshake = Handshake::new_client(net_id, pk, sk);
    let handshake = {
        let mut send_buf = [0; CLIENT_HELLO_BYTES];
        let handshake = handshake.send_client_hello(&mut send_buf)?;
        stream.write_all(&send_buf)?;
        handshake
    };
    let handshake = {
        let mut recv_buf = [0; SERVER_HELLO_BYTES];
        stream.read_exact(&mut recv_buf)?;
        handshake.recv_server_hello(&recv_buf)?
    };
    let handshake = {
        let mut send_buf = [0; CLIENT_AUTH_BYTES];
        let handshake = handshake.send_client_auth(&mut send_buf, server_pk)?;
        stream.write_all(&send_buf)?;
        handshake
    };
    let handshake = {
        let mut recv_buf = [0; SERVER_ACCEPT_BYTES];
        stream.read_exact(&mut recv_buf)?;
        handshake.recv_server_accept(&recv_buf)?
    };
    Ok(handshake.complete())
}

pub fn handshake_server_sync<T: Read + Write> (
        mut stream: T,
        net_id: auth::Key,
        pk: ed25519::PublicKey,
        sk: ed25519::SecretKey,
    ) -> Result<HandshakeComplete> {
    let handshake = Handshake::new_server(net_id, pk, sk);
    let handshake = {
        let mut recv_buf = [0; CLIENT_HELLO_BYTES];
        stream.read_exact(&mut recv_buf)?;
        handshake.recv_client_hello(&mut recv_buf)?
    };
    let handshake = {
        let mut send_buf = [0; SERVER_HELLO_BYTES];
        let handshake = handshake.send_server_hello(&mut send_buf)?;
        stream.write_all(&mut send_buf)?;
        handshake
    };
    let handshake = {
        let mut recv_buf = [0; CLIENT_AUTH_BYTES];
        stream.read_exact(&mut recv_buf)?;
        handshake.recv_client_auth(&mut recv_buf)?
    };
    let handshake = {
        let mut send_buf = [0; SERVER_ACCEPT_BYTES];
        let handshake = handshake.send_server_accept(&mut send_buf)?;
        stream.write_all(&mut send_buf)?;
        handshake
    };
    Ok(handshake.complete())
}
