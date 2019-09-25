#[macro_use]
extern crate arrayref;
extern crate sodiumoxide;

use std::pin::{
    Pin,
};

use std::cmp;

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

pub const MSG_BODY_MAX_LEN: usize = 4096;
pub const MSG_HEADER_LEN: usize = 34;

pub struct KeyNonce {
    key: secretbox::Key,
    nonce: secretbox::Nonce,
}

pub struct BoxStream<T: AsyncRead + AsyncWrite> {
    stream: T,
    send_key_nonce: KeyNonce,
    recv_key_nonce: KeyNonce,
    recv_buf: Vec<u8>,
    recv_buf_end: usize,
    recv_header: Option<[u8; MSG_HEADER_LEN]>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> BoxStream<T> {
    pub fn new(
        stream: T,
        recv_buf_len: usize,
        longterm_pk: ed25519::PublicKey,
        ephemeral_pk: curve25519::GroupElement,
        peer_longterm_pk: ed25519::PublicKey,
        peer_ephemeral_pk: curve25519::GroupElement,
        net_id: auth::Key,
        shared_secret_ab: curve25519::GroupElement,
        shared_secret_aB: curve25519::GroupElement,
        shared_secret_Ab: curve25519::GroupElement) -> Self {
        let recv_buf = vec![0; cmp::max(MSG_HEADER_LEN + MSG_BODY_MAX_LEN, recv_buf_len)];
        let recv_buf_end = 0;
        let recv_header = None;
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
        Self{ stream, send_key_nonce, recv_key_nonce, recv_buf, recv_buf_end, recv_header }
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> AsyncRead for BoxStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8]
    ) -> Poll<io::Result<usize>> {
        let recv_buf_end = self.recv_buf_end;
        let a = &mut self.stream;
        let b = &mut self.recv_buf;
        let pin = Pin::new(a);
        let poll = pin.poll_read(cx, &mut b[recv_buf_end..]);
        return poll;
        // match poll {
        //     Poll::Ready(Ok(n)) => {
        //         let end = self.recv_buf_end + n;
        //         let mut start = 0;
        //         loop {
        //             if end - start < MSG_HEADER_LEN {
        //                 return Poll::Pending;
        //             }
        //             let secret_header = &self.recv_buf[start..MSG_HEADER_LEN];
        //             let header = match secretbox::open(
        //                 secret_header,
        //                 &self.recv_key_nonce.nonce,
        //                 &self.recv_key_nonce.key
        //             ) {
        //                 Ok(h) => {
        //                     self.recv_key_nonce.nonce.increment_le_inplace();
        //                     h
        //                 },
        //                 Err(()) => {
        //                     return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other,
        //                                 "secretbox::open failed")));
        //                 }
        //             };
        //         }
        //     }
        //     Poll::Ready(Err(e)) => {
        //         return Poll::Ready(Err(e));
        //     }
        //     Poll::Pending => { return Poll::Pending }
        // }
    }
}

// impl AsyncWrite for BoxStream {
// 
// }

fn main() {

}
