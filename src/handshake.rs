extern crate sodiumoxide;

use sodiumoxide::crypto::{auth, hash::sha256, scalarmult::curve25519, secretbox, sign::ed25519};

#[derive(Debug)]
pub enum ScalarMultSk {
    Ephemeral,
    LongTerm,
}

#[derive(Debug)]
pub enum ScalarMultPk {
    ClientEphemeral,
    ClientLongTerm,
    ServerEphemeral,
    ServerLongTerm,
}

#[derive(Debug)]
pub enum Error {
    RecvServerHelloAuth,
    RecvServerAcceptSecretbox,
    RecvServerAcceptEd25519,
    RecvClientHelloAuth,
    RecvClientAuthSecretbox,
    RecvClientAuthEd25519,
    SendClientAuthScalarmult(ScalarMultSk, ScalarMultPk),
    RecvClientHelloScalarmult(ScalarMultSk, ScalarMultPk),
    RecvClientAuthScalarmult(ScalarMultSk, ScalarMultPk),
}

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
#[allow(non_snake_case)]
pub struct SharedSecretPartial {
    ab: curve25519::GroupElement,
    aB: curve25519::GroupElement,
}

#[derive(Debug, Clone, PartialEq)]
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
    pub fn send_client_hello(self, send_buf: &mut [u8]) -> Handshake<RecvServerHello> {
        concat_into!(
            send_buf,
            auth::authenticate(self.base.ephemeral_pk.as_ref(), &self.base.net_id).as_ref(),
            self.base.ephemeral_pk.as_ref()
        );
        let state = RecvServerHello;
        Handshake {
            base: self.base,
            state,
        }
    }
    pub const fn send_bytes(&self) -> usize {
        CLIENT_HELLO_BYTES
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
            return Err(Error::RecvServerHelloAuth);
        }
        Ok(Handshake {
            base: self.base,
            state: SendClientAuth {
                server_ephemeral_pk,
            },
        })
    }
    pub const fn recv_bytes(&self) -> usize {
        SERVER_HELLO_BYTES
    }
}

pub const CLIENT_AUTH_BYTES: usize = 112;

impl Handshake<SendClientAuth> {
    pub fn send_client_auth(
        self,
        send_buf: &mut [u8],
        server_pk: ed25519::PublicKey,
    ) -> Result<Handshake<RecvServerAccept>> {
        let fn_error = |a, b| Err(Error::SendClientAuthScalarmult(a, b));
        let shared_secret = SharedSecret {
            ab: curve25519::scalarmult(&self.base.ephemeral_sk, &self.state.server_ephemeral_pk)
                .or_else(|_| fn_error(
                    ScalarMultSk::Ephemeral,
                    ScalarMultPk::ServerEphemeral,
                ))?,
            aB: curve25519::scalarmult(&self.base.ephemeral_sk, &server_pk.to_curve25519()).or_else(
                |_| fn_error(ScalarMultSk::Ephemeral, ScalarMultPk::ServerLongTerm),
            )?,
            Ab: curve25519::scalarmult(
                &self.base.sk.to_curve25519(),
                &self.state.server_ephemeral_pk,
            )
            .or_else (|_| fn_error(
                ScalarMultSk::LongTerm,
                ScalarMultPk::ServerEphemeral,
            ))?,
        };

        let sig = ed25519::sign_detached(
            &concat!(
                auth::KEYBYTES + ed25519::PUBLICKEYBYTES + sha256::DIGESTBYTES,
                self.base.net_id.as_ref(),
                server_pk.as_ref(),
                sha256::hash(shared_secret.ab.as_ref()).as_ref()
            ),
            &self.base.sk,
        );

        let tag = secretbox::seal_detached(
            concat_into!(
                &mut send_buf[secretbox::MACBYTES..],
                sig.as_ref(),
                self.base.pk.as_ref()
            ),
            &secretbox::Nonce([0; 24]),
            &secretbox::Key(
                sha256::hash(&concat!(
                    auth::KEYBYTES + curve25519::GROUPELEMENTBYTES * 2,
                    self.base.net_id.as_ref(),
                    shared_secret.ab.as_ref(),
                    shared_secret.aB.as_ref()
                ))
                .0,
            ),
        );
        send_buf[..secretbox::MACBYTES].copy_from_slice(tag.as_ref());

        Ok(Handshake {
            base: self.base,
            state: RecvServerAccept {
                server_pk,
                server_ephemeral_pk: self.state.server_ephemeral_pk,
                shared_secret,
                sig,
            },
        })
    }
    pub const fn send_bytes(&self) -> usize {
        CLIENT_AUTH_BYTES
    }
}

impl Handshake<RecvServerAccept> {
    pub fn recv_server_accept(self, recv_buf: &mut [u8]) -> Result<Handshake<Complete>> {
        let (tag_buf, mut enc_buf) = recv_buf.split_at_mut(secretbox::MACBYTES);
        secretbox::open_detached(
            &mut enc_buf,
            &secretbox::Tag::from_slice(&tag_buf).unwrap(),
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
        .or(Err(Error::RecvServerAcceptSecretbox))?;
        let dec_buf = enc_buf;
        let sig = ed25519::Signature::from_slice(&dec_buf).unwrap();
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
            return Err(Error::RecvServerAcceptEd25519);
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
    pub const fn recv_bytes(&self) -> usize {
        SERVER_ACCEPT_BYTES
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
            return Err(Error::RecvClientHelloAuth);
        }
        let fn_error = |a, b| Err(Error::RecvClientHelloScalarmult(a, b));
        let shared_secret_partial = SharedSecretPartial {
            ab: curve25519::scalarmult(&self.base.ephemeral_sk, &client_ephemeral_pk).or_else(
                |_| fn_error(ScalarMultSk::Ephemeral, ScalarMultPk::ClientEphemeral),
            )?,
            aB: curve25519::scalarmult(&self.base.sk.to_curve25519(), &client_ephemeral_pk).or_else(
                |_| fn_error(ScalarMultSk::LongTerm, ScalarMultPk::ClientEphemeral),
            )?,
        };
        Ok(Handshake {
            base: self.base,
            state: SendServerHello {
                client_ephemeral_pk,
                shared_secret_partial,
            },
        })
    }
    pub const fn recv_bytes(&self) -> usize {
        CLIENT_HELLO_BYTES
    }
}

pub const SERVER_HELLO_BYTES: usize = 64;

impl Handshake<SendServerHello> {
    pub fn send_server_hello(self, send_buf: &mut [u8]) -> Handshake<RecvClientAuth> {
        concat_into!(
            send_buf,
            auth::authenticate(self.base.ephemeral_pk.as_ref(), &self.base.net_id).as_ref(),
            self.base.ephemeral_pk.as_ref()
        );
        Handshake {
            base: self.base,
            state: RecvClientAuth {
                client_ephemeral_pk: self.state.client_ephemeral_pk,
                shared_secret_partial: self.state.shared_secret_partial,
            },
        }
    }
    pub const fn send_bytes(&self) -> usize {
        SERVER_HELLO_BYTES
    }
}

impl Handshake<RecvClientAuth> {
    pub fn recv_client_auth(self, recv_buf: &mut [u8]) -> Result<Handshake<SendServerAccept>> {
        let (tag_buf, mut enc_buf) = recv_buf.split_at_mut(secretbox::MACBYTES);
        secretbox::open_detached(
            &mut enc_buf,
            &secretbox::Tag::from_slice(&tag_buf).unwrap(),
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
        .or(Err(Error::RecvClientAuthSecretbox))?;
        let dec_buf = enc_buf;
        let client_sig = ed25519::Signature::from_slice(&dec_buf[..64]).unwrap();
        let client_pk = ed25519::PublicKey::from_slice(&dec_buf[64..]).unwrap();
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
            return Err(Error::RecvClientAuthEd25519);
        }
        let fn_error = |a, b| Err(Error::RecvClientHelloScalarmult(a, b));
        let shared_secret = SharedSecret {
            ab: self.state.shared_secret_partial.ab,
            aB: self.state.shared_secret_partial.aB,
            Ab: curve25519::scalarmult(&self.base.ephemeral_sk, &client_pk.to_curve25519()).or_else(
                |_| fn_error(ScalarMultSk::Ephemeral, ScalarMultPk::ClientLongTerm),
            )?,
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
    pub const fn recv_bytes(&self) -> usize {
        CLIENT_AUTH_BYTES
    }
}

pub const SERVER_ACCEPT_BYTES: usize = 80;

impl Handshake<SendServerAccept> {
    pub fn send_server_accept(self, send_buf: &mut [u8]) -> Handshake<Complete> {
        let sig = ed25519::sign_detached(
            &concat!(
                auth::KEYBYTES
                    + ed25519::SIGNATUREBYTES
                    + ed25519::PUBLICKEYBYTES
                    + sha256::DIGESTBYTES,
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
                sha256::hash(&concat!(
                    auth::KEYBYTES + curve25519::GROUPELEMENTBYTES * 3,
                    self.base.net_id.as_ref(),
                    self.state.shared_secret.ab.as_ref(),
                    self.state.shared_secret.aB.as_ref(),
                    self.state.shared_secret.Ab.as_ref()
                ))
                .0,
            ),
        );
        send_buf[..secretbox::MACBYTES].copy_from_slice(tag.as_ref());

        Handshake {
            base: self.base,
            state: Complete {
                peer_pk: self.state.client_pk,
                peer_ephemeral_pk: self.state.client_ephemeral_pk,
                shared_secret: self.state.shared_secret,
            },
        }
    }
    pub const fn send_bytes(&self) -> usize {
        SERVER_ACCEPT_BYTES
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
    pub fn complete(&self) -> HandshakeComplete {
        HandshakeComplete {
            net_id: self.base.net_id.clone(),
            pk: self.base.pk,
            ephemeral_pk: self.base.ephemeral_pk.clone(),
            peer_pk: self.state.peer_pk,
            peer_ephemeral_pk: self.state.peer_ephemeral_pk.clone(),
            shared_secret: self.state.shared_secret.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake() {
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

        let hs_client = Handshake::new_client(net_id.clone(), client_pk, client_sk);
        let hs_server = Handshake::new_server(net_id, server_pk, server_sk);

        let (hs_client, hs_server) = {
            let mut client_buf = [0; CLIENT_HELLO_BYTES];
            let hs_client = hs_client.send_client_hello(&mut client_buf);
            let hs_server = hs_server.recv_client_hello(&mut client_buf).unwrap();
            (hs_client, hs_server)
        };
        let (hs_client, hs_server) = {
            let mut server_buf = [0; SERVER_HELLO_BYTES];
            let hs_server = hs_server.send_server_hello(&mut server_buf);
            let hs_client = hs_client.recv_server_hello(&mut server_buf).unwrap();
            (hs_client, hs_server)
        };
        let (hs_client, hs_server) = {
            let mut client_buf = [0; CLIENT_AUTH_BYTES];
            let hs_client = hs_client
                .send_client_auth(&mut client_buf, server_pk)
                .unwrap();
            let hs_server = hs_server.recv_client_auth(&mut client_buf).unwrap();
            (hs_client, hs_server)
        };
        let (hs_client, hs_server) = {
            let mut server_buf = [0; SERVER_ACCEPT_BYTES];
            let hs_server = hs_server.send_server_accept(&mut server_buf);
            let hs_client = hs_client.recv_server_accept(&mut server_buf).unwrap();
            (hs_client, hs_server)
        };

        let complete_client = hs_client.complete();
        let complete_server = hs_server.complete();

        assert_eq!(complete_client.net_id, complete_server.net_id);
        assert_eq!(complete_client.shared_secret, complete_server.shared_secret);
        assert_eq!(complete_client.pk, complete_server.peer_pk);
        assert_eq!(
            complete_client.ephemeral_pk,
            complete_server.peer_ephemeral_pk
        );
        assert_eq!(complete_client.peer_pk, complete_server.pk);
        assert_eq!(
            complete_client.peer_ephemeral_pk,
            complete_server.ephemeral_pk
        );
    }
}
