#[macro_use]
extern crate arrayref;
extern crate sodiumoxide;

use std::pin::{
    Pin,
};

use sodiumoxide::crypto::{
    secretbox,
    hash::sha256,
    sign::ed25519,
    auth,
    scalarmult::curve25519,
};
use futures::io;
use futures::io::{
    AsyncRead,
    AsyncWrite,
};
use futures::task::{
    Context,
    Poll,
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

impl<T: AsyncRead + AsyncWrite + Unpin> BoxStream<T> {
    pub fn new(
        stream: T,
        longterm_pk: ed25519::PublicKey,
        ephemeral_pk: curve25519::GroupElement,
        peer_longterm_pk: ed25519::PublicKey,
        peer_ephemeral_pk: curve25519::GroupElement,
        net_id: auth::Key,
        shared_secret_ab: curve25519::GroupElement,
        shared_secret_aB: curve25519::GroupElement,
        shared_secret_Ab: curve25519::GroupElement) -> Self {
        let shared_secret_0 = sha256::hash(
                &[
                    net_id.as_ref(),
                    shared_secret_ab.as_ref(),
                    shared_secret_aB.as_ref(),
                    shared_secret_Ab.as_ref(),
                ].concat()
            );
        let shared_secret_1 = sha256::hash(shared_secret_0.as_ref());
        let send_hmac_nonce = auth::authenticate(peer_ephemeral_pk.as_ref(), &net_id);
        let send_key_nonce = KeyNonce {
            key: secretbox::Key(sha256::hash(&[
                         shared_secret_1.as_ref(),
                         peer_longterm_pk.as_ref(),
            ].concat()).0),
            nonce: secretbox::Nonce( *array_ref![ send_hmac_nonce.as_ref(), 0, 24]),
        };
        let recv_hmac_nonce = auth::authenticate(ephemeral_pk.as_ref(), &net_id);
        let recv_key_nonce = KeyNonce {
            key: secretbox::Key(sha256::hash(&[
                         shared_secret_1.as_ref(),
                         longterm_pk.as_ref(),
            ].concat()).0),
            nonce: secretbox::Nonce( *array_ref![ recv_hmac_nonce.as_ref(), 0, 24]),
        };
        Self{ stream, send_key_nonce, recv_key_nonce }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for BoxStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8]
    ) -> Poll<io::Result<usize>> {
        let mut header = [0; 34];
        Pin::new(&mut self.stream).poll_read(cx, &mut header)
    }
}

// impl AsyncWrite for BoxStream {
// 
// }

fn main() {

}
