extern crate sodiumoxide;

use super::boxstream::BoxStream;

use sodiumoxide::crypto::{auth, hash::sha256, scalarmult::curve25519, secretbox, sign::ed25519};
use async_std::{
    prelude::*,
    io,
    io::Read,
    io::Result,
    io::Write
};

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
pub struct HandshakeBase<R, W> {
    read_stream: R,
    write_stream: W,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
    ephemeral_pk: curve25519::GroupElement,
    ephemeral_sk: curve25519::Scalar,
}

#[derive(Debug)]
pub struct Handshake<R, W, S: State> {
    pub base: HandshakeBase<R, W>,
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

// Client
impl<R, W> Handshake<R, W, SendClientHello> {
    pub fn new_client(
        read_stream: R,
        write_stream: W,
        net_id: auth::Key,
        pk: ed25519::PublicKey,
        sk: ed25519::SecretKey,
    ) -> Handshake<R, W, SendClientHello> {
        let (ephemeral_ed_pk, ephemeral_ed_sk) = ed25519::gen_keypair();
        let ephemeral_pk = ephemeral_ed_pk.to_curve25519();
        let ephemeral_sk = ephemeral_ed_sk.to_curve25519();
        let state = SendClientHello;
        let base = HandshakeBase {
            read_stream,
            write_stream,
            net_id,
            pk,
            sk,
            ephemeral_pk,
            ephemeral_sk,
        };
        Handshake { base, state }
    }
}

impl<R, W: Write+Unpin> Handshake<R, W, SendClientHello> {
    pub async fn send_client_hello(mut self) -> Result<Handshake<R, W, RecvServerHello>> {
        let send = [
            auth::authenticate(self.base.ephemeral_pk.as_ref(), &self.base.net_id).as_ref(),
            self.base.ephemeral_pk.as_ref(),
        ]
        .concat();
        self.base.write_stream.write_all(&send).await?;
        self.base.write_stream.flush().await?;
        let state = RecvServerHello;
        Ok(Handshake {
            base: self.base,
            state,
        })
    }
}

impl<R: Read+Unpin, W> Handshake<R, W, RecvServerHello> {
    pub async fn recv_server_hello(mut self) -> Result<Handshake<R, W, SendClientAuth>> {
        let mut recv = [0; 64];
        self.base.read_stream.read_exact(&mut recv).await?;
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
}

impl<R, W: Write+Unpin> Handshake<R, W, SendClientAuth> {
    pub async fn send_client_auth(
        mut self,
        server_pk: ed25519::PublicKey,
    ) -> Result<Handshake<R, W, RecvServerAccept>> {
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
            &[
                self.base.net_id.as_ref(),
                server_pk.as_ref(),
                sha256::hash(shared_secret.ab.as_ref()).as_ref(),
            ]
            .concat(),
            &self.base.sk,
        );
        let send = secretbox::seal(
            &[sig.as_ref(), self.base.pk.as_ref()].concat(),
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(
                sha256::hash(
                    &[
                        self.base.net_id.as_ref(),
                        shared_secret.ab.as_ref(),
                        shared_secret.aB.as_ref(),
                    ]
                    .concat(),
                )
                .0,
            ),
        );
        self.base.write_stream.write_all(&send).await?;
        self.base.write_stream.flush().await?;
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

impl<R: Read+Unpin, W> Handshake<R, W, RecvServerAccept> {
    pub async fn recv_server_accept(mut self) -> Result<Handshake<R, W, Complete>> {
        let mut recv_enc = [0; 80];
        self.base.read_stream.read_exact(&mut recv_enc).await?;
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

impl<R: Read+Unpin, W> Handshake<R, W, RecvClientHello> {
    pub async fn recv_client_hello(mut self) -> Result<Handshake<R, W, SendServerHello>> {
        let mut recv = [0; 64];
        self.base.read_stream.read_exact(&mut recv).await?;
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
}

impl<R, W: Write+Unpin> Handshake<R, W, SendServerHello> {
    pub async fn send_server_hello(mut self) -> Result<Handshake<R, W, RecvClientAuth>> {
        let send = [
            auth::authenticate(self.base.ephemeral_pk.as_ref(), &self.base.net_id).as_ref(),
            self.base.ephemeral_pk.as_ref(),
        ]
        .concat();
        self.base.write_stream.write_all(&send).await?;
        self.base.write_stream.flush().await?;
        Ok(Handshake {
            base: self.base,
            state: RecvClientAuth {
                client_ephemeral_pk: self.state.client_ephemeral_pk,
                shared_secret_partial: self.state.shared_secret_partial,
            },
        })
    }
}

impl<R: Read+Unpin, W> Handshake<R, W, RecvClientAuth> {
    pub async fn recv_client_auth(mut self) -> Result<Handshake<R, W, SendServerAccept>> {
        let mut recv_enc = [0; 112];
        self.base.read_stream.read_exact(&mut recv_enc).await?;
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
}

impl<R, W: Write+Unpin> Handshake<R, W, SendServerAccept> {
    pub async fn send_server_accept(mut self) -> Result<Handshake<R, W, Complete>> {
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
        self.base.write_stream.write_all(&send).await?;
        self.base.write_stream.flush().await?;
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

impl<R:Read+Unpin, W:Write+Unpin> Handshake<R, W, Complete> {
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
