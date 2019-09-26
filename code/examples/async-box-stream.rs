#[macro_use]
extern crate arrayref;
extern crate sodiumoxide;

use std::{
    pin::Pin,
    cmp,
};
use sodiumoxide::crypto::{
    secretbox,
    hash::sha256,
    sign::ed25519,
    auth,
    scalarmult::curve25519,
};
use futures::io::{
    self,
    AsyncRead,
    AsyncWrite,
};
use futures::task::{
    Context,
    Poll,
};

// Length of encrypted body (with MAC detached)
pub const MSG_BODY_MAX_LEN: usize = 4096;
// Length of decrypted header (body_len || enc_body_mac)
pub const MSG_HEADER_DEC_LEN: usize = 18;
// Length of encrypted header (with MAC prefixed)
pub const MSG_HEADER_LEN: usize = MSG_HEADER_DEC_LEN + secretbox::MACBYTES;

pub struct KeyNonce {
    key: secretbox::Key,
    nonce: secretbox::Nonce,
}

pub struct Header {
    body_len: usize,
    body_mac: [u8; secretbox::MACBYTES],
}

impl Header {
    pub fn from_bytes(buf: &[u8; MSG_HEADER_DEC_LEN]) -> Self {
        Self{
            body_len: u16::from_be_bytes(*array_ref![buf[..2], 0, 2]) as usize,
            body_mac: *array_ref![buf[2..], 0, 16],
        }
    }

    pub fn to_bytes(&self) -> [u8; MSG_HEADER_DEC_LEN] {
        let buf = [
            (self.body_len as u16).to_be_bytes().as_ref(),
            self.body_mac.as_ref(),
        ].concat();
        *array_ref![buf, 0, 18]
    }
}

pub struct BoxStream<T> {
    stream: T,
    send_key_nonce: KeyNonce,
    recv: BoxStreamRecv,
}

struct BoxStreamRecv {
    key_nonce: KeyNonce,
    buf: Box<[u8]>,
    buf_cap: usize,
    dec: Box<[u8]>,
    dec_pos: usize,
    dec_cap: usize,
    header: Option<Header>,
}

impl<T> BoxStream<T> {
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
        let capacity = cmp::max(MSG_HEADER_LEN + MSG_BODY_MAX_LEN, recv_buf_len);
        let recv = BoxStreamRecv {
            key_nonce: recv_key_nonce,
            buf: vec![0; capacity].into_boxed_slice(),
            buf_cap: 0,
            dec: vec![0; capacity].into_boxed_slice(),
            dec_pos: 0,
            dec_cap: 0,
            header: None,
        };
        Self{ stream, send_key_nonce, recv }
    }
}

// Decrypt BoxStream messages from recv.buf into recv.dec.  Return the position of the first
// non-decrypted byte in recv.buf.
fn decrypt_box_stream(recv: &mut BoxStreamRecv) -> io::Result<usize> {
    let mut buf_pos = 0;
    // Decrypt messages from the recv.buf in a loop
    loop {
        // The first part of a BoxStream message is a fixed length header
        let header = match recv.header {
            // Use the header from the previous header box decryption
            Some(ref header) => {
                header
            }
            // Try to decrypt the header from the received buffer
            None => {
                if recv.buf_cap - buf_pos < MSG_HEADER_LEN {
                    return Ok(buf_pos);
                }
                let secret_header = &recv.buf[buf_pos..buf_pos+MSG_HEADER_LEN];
                buf_pos += MSG_HEADER_LEN;
                let header = match secretbox::open(
                    secret_header,
                    &recv.key_nonce.nonce,
                    &recv.key_nonce.key
                ) {
                    Ok(h) => {
                        recv.key_nonce.nonce.increment_le_inplace();
                        recv.header = Some(Header::from_bytes(array_ref![&h, 0, 18]));
                        recv.header.as_ref().unwrap()
                    },
                    Err(()) => {
                        return Err(io::Error::new(io::ErrorKind::Other,
                                "secretbox::open for header failed"));
                    }
                };
                header
            }
        };
        // The second part of a BoxStream message is a variable length body
        if recv.buf_cap - buf_pos < header.body_len {
            return Ok(buf_pos);
        }
        let secret_body = &[
            header.body_mac.as_ref(),
            &recv.buf[buf_pos..buf_pos+header.body_len]
        ].concat();
        buf_pos += header.body_len;
        let body = match secretbox::open(
            secret_body,
            &recv.key_nonce.nonce,
            &recv.key_nonce.key
        ) {
            Ok(b) => {
                recv.key_nonce.nonce.increment_le_inplace();
                b
            },
            Err(()) => {
                return Err(io::Error::new(io::ErrorKind::Other,
                        "secretbox::open for body failed"));
            }
        };
        recv.dec[recv.dec_cap..recv.dec_cap + body.len()].copy_from_slice(&body);
        buf_pos += body.len();
        recv.dec_cap += body.len();
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for BoxStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8]
    ) -> Poll<io::Result<usize>> {
        let BoxStream { stream, recv, .. } = self.get_mut();
        // Decrypted buffer is empty, we must fill it
        if recv.dec_pos == recv.dec_pos {
            recv.dec_pos = 0;
            recv.dec_cap = 0;
            let poll = Pin::new(stream).poll_read(cx, &mut recv.buf[recv.buf_cap..]);
            match poll {
                Poll::Ready(Ok(n)) => {
                    recv.buf_cap += n;
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => { return Poll::Pending; }
            }
            match decrypt_box_stream(recv) {
                Err(e) => { return Poll::Ready(Err(e)); }
                Ok(buf_pos) => {
                    // Reset recv.buf by forgetting the decrypted bytes and moving the decrypted
                    // bytes to the beginning.
                    recv.buf.copy_within(buf_pos..recv.buf_cap, 0);
                    recv.buf_cap = recv.buf_cap - buf_pos;
                }
            }
        }
        // We have some decrypted data to give back
        if recv.dec_pos < recv.dec_pos {
            let len = cmp::min(buf.len(), recv.dec_cap - recv.dec_pos);
            buf[..len].copy_from_slice(&recv.dec[recv.dec_pos..recv.dec_pos+len]);
            recv.dec_pos += len;
            return Poll::Ready(Ok(len));
        }
        return Poll::Pending;
    }
}

// impl AsyncWrite for BoxStream {
// 
// }

fn main() {

}
