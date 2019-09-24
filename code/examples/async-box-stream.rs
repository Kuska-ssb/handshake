#[macro_use]
extern crate arrayref;
extern crate sodiumoxide;

use sodiumoxide::crypto::{
    secretbox,
    hash::sha256,
    sign::ed25519,
    auth,
    scalarmult::curve25519,
};
use futures::io::{
    AsyncRead,
    AsyncWrite,
};

pub struct KeyNonce {
    key: secretbox::Key,
    nonce: secretbox::Nonce,
}

pub struct BoxStream<T: AsyncRead + AsyncWrite> {
    stream: T,
    send_key_nonce: KeyNonce,
    recv_key_nonce: KeyNonce,
}

impl<T: AsyncRead + AsyncWrite> BoxStream<T> {
    pub fn new(stream: T,
        peer_longterm_pk: ed25519::PublicKey,
        peer_ephemeral_pk: curve25519::GroupElement,
        net_id: auth::Key,
        shared_secret_ab: curve25519::GroupElement,
        shared_secret_aB: curve25519::GroupElement,
        shared_secret_Ab: curve25519::GroupElement) -> Self {
        let send_key_nonce = KeyNonce {
            key: secretbox::Key(sha256::hash(
                &[
                    net_id.as_ref(),
                    shared_secret_ab.as_ref(),
                    shared_secret_aB.as_ref(),
                    shared_secret_Ab.as_ref(),
                ].concat()
            ).0),
            nonce: secretbox::Nonce(
                *array_ref![
                    auth::authenticate(peer_ephemeral_pk.as_ref(), &net_id).as_ref(),
                0, 24]
            ),
        };
    }
}

fn main() {

}
