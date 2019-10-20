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

#[derive(Debug)]
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
    pub peer_pk: ed25519::PublicKey,
    pub peer_ephemeral_pk: curve25519::GroupElement,
    pub shared_secret: SharedSecret,
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
                $dst[n..n + $x.len()].copy_from_slice($x);
                n += $x.len();
            )*
            $dst
        }
    };
}

macro_rules! concat {
    ( $( $x:expr ),* ; $n:expr ) => {
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

impl Handshake<SendClientHello> {
    pub fn send_client_hello(mut self, send_buf: &mut [u8]) -> Result<Handshake<RecvServerHello>> {
        concat_into!(send_buf,
            auth::authenticate(self.base.ephemeral_pk.as_ref(), &self.base.net_id).as_ref(),
            self.base.ephemeral_pk.as_ref());
        let state = RecvServerHello;
        Ok(Handshake {
            base: self.base,
            state,
        })
    }
    pub const fn send_bytes(&self) -> usize {
        64
    }
}

impl<R: Read, W> Handshake<R, W, RecvServerHello> {
    pub fn recv_server_hello(mut self) -> Result<Handshake<R, W, SendClientAuth>> {
        let mut recv = [0; 64];
        self.base.read_stream.read_exact(&mut recv)?;
        let server_hmac = auth::Tag::from_slice(&recv[..32]).unwrap();
        let server_ephemeral_pk = curve25519::GroupElement::from_slice(&recv[32..]).unwrap();
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
    pub fn recv_bytes(&self) -> usize {
        64
    }
}

impl Handshake<SendClientAuth> {
    pub fn send_client_auth(
        mut self,
        send_buf: &mut [u8],
        server_pk: ed25519::PublicKey,
    ) -> Result<Handshake<RecvServerAccept>> {
        let mut buf = Buffer::new(send_buf);
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
            concat!(
                self.base.net_id.as_ref(),
                server_pk.as_ref(),
                sha256::hash(shared_secret.ab.as_ref())
            ; 32 * 3),
            &self.base.sk);

        let tag = secretbox::seal_detached(
            concat_into!(send_buf[secretbox::MACBYTES..], sig.as_ref(), self.base.pk.as_ref()),
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(sha256::hash(
                    concat!(
                        self.base.net_id.as_ref(),
                        shared_secret.ab.as_ref(),
                        shared_secret.aB.as_ref()
                    ; 32 * 3
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
    pub fn send_bytes(&self) -> usize {
        112
    }
}

impl<R: Read, W> Handshake<R, W, RecvServerAccept> {
    pub fn recv_server_accept(mut self) -> Result<Handshake<R, W, Complete>> {
        let mut recv_enc = [0; 80];
        self.base.read_stream.read_exact(&mut recv_enc)?;
        let recv = secretbox::open(
            &recv_enc,
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
    pub fn recv_bytes(&self) -> usize {
        80
    }
}

// Server
impl<R, W> Handshake<R, W, RecvClientHello> {
    pub fn new_server(
        read_stream: R,
        write_stream: W,
        net_id: auth::Key,
        pk: ed25519::PublicKey,
        sk: ed25519::SecretKey,
    ) -> Handshake<R, W, RecvClientHello> {
        let (ephemeral_ed_pk, ephemeral_ed_sk) = ed25519::gen_keypair();
        let ephemeral_pk = ephemeral_ed_pk.to_curve25519();
        let ephemeral_sk = ephemeral_ed_sk.to_curve25519();
        Handshake {
            base: HandshakeBase {
                read_stream,
                write_stream,
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

impl<R: Read, W> Handshake<R, W, RecvClientHello> {
    pub fn recv_client_hello(mut self) -> Result<Handshake<R, W, SendServerHello>> {
        let mut recv = [0; 64];
        self.base.read_stream.read_exact(&mut recv)?;
        let client_hmac = auth::Tag::from_slice(&recv[..32]).unwrap();
        let client_ephemeral_pk = curve25519::GroupElement::from_slice(&recv[32..]).unwrap();
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
    pub fn recv_bytes(&self) -> usize {
        64
    }
}

impl<R, W: Write> Handshake<R, W, SendServerHello> {
    pub fn send_server_hello(mut self) -> Result<Handshake<R, W, RecvClientAuth>> {
        let send = [
            auth::authenticate(self.base.ephemeral_pk.as_ref(), &self.base.net_id).as_ref(),
            self.base.ephemeral_pk.as_ref(),
        ]
        .concat();
        self.base.write_stream.write_all(&send)?;
        self.base.write_stream.flush()?;
        Ok(Handshake {
            base: self.base,
            state: RecvClientAuth {
                client_ephemeral_pk: self.state.client_ephemeral_pk,
                shared_secret_partial: self.state.shared_secret_partial,
            },
        })
    }
    pub fn send_bytes(&self) -> usize {
        64
    }
}

impl<R: Read, W> Handshake<R, W, RecvClientAuth> {
    pub fn recv_client_auth(mut self) -> Result<Handshake<R, W, SendServerAccept>> {
        let mut recv_enc = [0; 112];
        self.base.read_stream.read_exact(&mut recv_enc)?;
        let recv = secretbox::open(
            &recv_enc,
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
    pub fn recv_bytes(&self) -> usize {
        112
    }
}

impl<R, W: Write> Handshake<R, W, SendServerAccept> {
    pub fn send_server_accept(mut self) -> Result<Handshake<R, W, Complete>> {
        let sig = ed25519::sign_detached(
            &[
                self.base.net_id.as_ref(),
                self.state.client_sig.as_ref(),
                self.state.client_pk.as_ref(),
                sha256::hash(self.state.shared_secret.ab.as_ref()).as_ref(),
            ]
            .concat(),
            &self.base.sk,
        );
        let send = secretbox::seal(
            sig.as_ref(),
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
        );
        self.base.write_stream.write_all(&send)?;
        self.base.write_stream.flush()?;
        Ok(Handshake {
            base: self.base,
            state: Complete {
                peer_pk: self.state.client_pk,
                peer_ephemeral_pk: self.state.client_ephemeral_pk,
                shared_secret: self.state.shared_secret,
            },
        })
    }
    pub fn send_bytes(&self) -> usize {
        80
    }
}

impl<R, W> Handshake<R, W, Complete> {
    pub fn to_box_stream(self, recv_buf_len: usize) -> BoxStream<R, W> {
        BoxStream::new(
            self.base.read_stream,
            self.base.write_stream,
            recv_buf_len,
            self.base.net_id,
            self.base.pk,
            self.base.ephemeral_pk,
            self.state.peer_pk,
            self.state.peer_ephemeral_pk,
            self.state.shared_secret,
        )
    }
}
