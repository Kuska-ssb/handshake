extern crate log;
extern crate sodiumoxide;

use crate::handshake::HandshakeComplete;

use core::fmt;
use core::{cmp, mem};
use sodiumoxide::crypto::{auth, hash::sha256, scalarmult::curve25519, secretbox};
use std::convert;
use std::io;

/// Max length of encrypted body (with MAC detached)
pub const MSG_BODY_MAX_LEN: usize = 4096;
/// Length of decrypted header (body_len || enc_body_mac)
pub const MSG_HEADER_DEC_LEN: usize = 18;
/// Length of encrypted header (with MAC prefixed)
pub const MSG_HEADER_LEN: usize = MSG_HEADER_DEC_LEN + secretbox::MACBYTES;

/// The error type for boxstream operations.  Errors originate from decryption errors.
#[derive(Debug)]
pub enum Error {
    DecryptHeaderSecretbox,
    DecryptBodySecretbox,
}

impl std::error::Error for Error {}

impl convert::From<Error> for io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::DecryptHeaderSecretbox => Self::new(io::ErrorKind::InvalidInput, error),
            Error::DecryptBodySecretbox => Self::new(io::ErrorKind::InvalidInput, error),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DecryptHeaderSecretbox => {
                write!(f, "secretbox::open failed in header decryption")
            }
            Error::DecryptBodySecretbox => write!(f, "secretbox::open failed in body decryption"),
        }
    }
}

/// The result type for boxstream operations.
pub type Result<T> = std::result::Result<T, Error>;

/// A pair of key and nonce used for encryption/decryption of every message in the boxstream.
pub struct KeyNonce {
    key: secretbox::Key,
    nonce: secretbox::Nonce,
}

impl KeyNonce {
    /// Creates a new `KeyNonce` from a key and a nonce.
    pub fn new(key: secretbox::Key, nonce: secretbox::Nonce) -> Self {
        Self { key, nonce }
    }
    /// Derives the sender and receiver `KeyNonce` from a `HandshakeComplete`.  Returns
    /// `(key_nonce_send, key_nonce_recv)`.
    pub fn from_handshake(handshake_complete: HandshakeComplete) -> (Self, Self) {
        let HandshakeComplete {
            net_id,
            pk,
            ephemeral_pk,
            peer_pk,
            peer_ephemeral_pk,
            shared_secret,
        } = handshake_complete;
        let shared_secret_0 = sha256::hash(&concat!(
            auth::KEYBYTES + curve25519::GROUPELEMENTBYTES * 3,
            net_id.as_ref(),
            shared_secret.ab.as_ref(),
            shared_secret.aB.as_ref(),
            shared_secret.Ab.as_ref()
        ));
        let shared_secret_1 = sha256::hash(shared_secret_0.as_ref());
        let send_hmac_nonce = auth::authenticate(peer_ephemeral_pk.as_ref(), &net_id);
        let key_nonce_send = KeyNonce {
            key: secretbox::Key(
                sha256::hash(&[shared_secret_1.as_ref(), peer_pk.as_ref()].concat()).0,
            ),
            nonce: secretbox::Nonce::from_slice(&send_hmac_nonce.as_ref()[..secretbox::NONCEBYTES])
                .unwrap(),
        };
        let recv_hmac_nonce = auth::authenticate(ephemeral_pk.as_ref(), &net_id);
        let key_nonce_recv = KeyNonce {
            key: secretbox::Key(sha256::hash(&[shared_secret_1.as_ref(), pk.as_ref()].concat()).0),
            nonce: secretbox::Nonce::from_slice(&recv_hmac_nonce.as_ref()[..secretbox::NONCEBYTES])
                .unwrap(),
        };
        (key_nonce_send, key_nonce_recv)
    }

    /// Increments the nonce value by one.  The nonce value is encoded/decoded in big endian,
    /// following the boxstream spec.
    pub fn increment_nonce_be_inplace(&mut self) {
        for n in (0..self.nonce.0.len()).rev() {
            let (inc, _) = self.nonce.0[n].overflowing_add(1);
            self.nonce.0[n] = inc;
            if self.nonce.0[n] != 0 {
                break;
            }
        }
    }
}

/// The header of a message in the boxstream.
#[derive(Debug)]
pub struct Header {
    body_len: usize,
    body_mac: secretbox::Tag,
}

impl Header {
    /// Decodes `MSG_HEADER_DEC_LEN` length byte array to build a `Header`.
    pub fn from_bytes(buf: &[u8; MSG_HEADER_DEC_LEN]) -> Self {
        Self {
            body_len: u16::from_be_bytes([buf[0], buf[1]]) as usize,
            body_mac: secretbox::Tag::from_slice(&buf[2..]).unwrap(),
        }
    }

    /// Decodes `MSG_HEADER_DEC_LEN` bytes from a slice to build a `Header`.
    pub fn from_slice(buf: &[u8]) -> Option<Self> {
        if buf.len() != MSG_HEADER_DEC_LEN {
            return None;
        }
        Some(Self {
            body_len: u16::from_be_bytes([buf[0], buf[1]]) as usize,
            body_mac: secretbox::Tag::from_slice(&buf[2..]).unwrap(),
        })
    }

    /// Encodes the `Header` to a byte array.
    pub fn to_bytes(&self) -> [u8; MSG_HEADER_DEC_LEN] {
        concat!(
            MSG_HEADER_DEC_LEN,
            (self.body_len as u16).to_be_bytes().as_ref(),
            self.body_mac.as_ref()
        )
    }
}

/// Encrypt the final goodbye message into `enc`.  Returns the number of bytes written into `enc`.
///
/// Note that the nonce is not incremented since this **must** be the last nonce used.
fn encrypt_box_stream_goodbye(key_nonce: &mut KeyNonce, enc: &mut [u8]) -> usize {
    let (goodbye_tag_buf, mut goodbye_header_buf) =
        enc[..MSG_HEADER_LEN].split_at_mut(secretbox::MACBYTES);
    goodbye_header_buf.iter_mut().for_each(|x| *x = 0);

    let goodbye_tag =
        secretbox::seal_detached(&mut goodbye_header_buf, &key_nonce.nonce, &key_nonce.key);
    goodbye_tag_buf.copy_from_slice(goodbye_tag.as_ref());
    MSG_HEADER_LEN
}

/// Encrypt a single message from `buf` into `enc`.  Return the number of bytes read
/// from `buf` and the number of bytes written into `enc`.
fn encrypt_box_stream_msg(key_nonce: &mut KeyNonce, buf: &[u8], enc: &mut [u8]) -> (usize, usize) {
    let body = &buf[..cmp::min(buf.len(), MSG_BODY_MAX_LEN)];

    let header_nonce = key_nonce.nonce;
    key_nonce.increment_nonce_be_inplace();
    let body_nonce = key_nonce.nonce;
    key_nonce.increment_nonce_be_inplace();

    let (header_buf, mut body_buf) =
        enc[..MSG_HEADER_LEN + body.len()].split_at_mut(MSG_HEADER_LEN);
    let (header_tag_buf, mut header_body_buf) = header_buf.split_at_mut(secretbox::MACBYTES);
    body_buf.copy_from_slice(body);
    let body_tag = secretbox::seal_detached(&mut body_buf, &body_nonce, &key_nonce.key);
    let header = Header {
        body_len: body.len(),
        body_mac: body_tag,
    };
    header_body_buf.copy_from_slice(&header.to_bytes());
    let header_tag = secretbox::seal_detached(&mut header_body_buf, &header_nonce, &key_nonce.key);
    header_tag_buf.copy_from_slice(header_tag.as_ref());
    (body.len(), MSG_HEADER_LEN + body.len())
}

/// The transport agnostic boxstream sending side.
pub struct BoxStreamSend {
    key_nonce: KeyNonce,
}

impl BoxStreamSend {
    /// Create a new `BoxStreamSend` from the `key_nonce`.
    pub fn new(key_nonce: KeyNonce) -> Self {
        Self { key_nonce }
    }
    /// Encrypt a single boxstream message by taking bytes from `buf` and encrypting them into
    /// `enc`.  Returns the number of bytes read from `buf` and the number of bytes written into
    /// `enc`.
    pub fn encrypt(&mut self, buf: &[u8], mut enc: &mut [u8]) -> (usize, usize) {
        encrypt_box_stream_msg(&mut self.key_nonce, buf, &mut enc)
    }
    /// Encript a goodbye message into `enc`.  Returns the number of bytes written into `enc`.
    pub fn encrypt_goodbye(&mut self, enc: &mut [u8]) -> usize {
        encrypt_box_stream_goodbye(&mut self.key_nonce, &mut enc[..])
    }
}

/// Decrypt and decode a boxstream `Header` from `buf`.
fn decrypt_box_stream_header(key_nonce: &mut KeyNonce, buf: &mut [u8]) -> Result<Header> {
    let (header_tag_buf, mut header_body_buf) =
        buf[..MSG_HEADER_LEN].split_at_mut(secretbox::MACBYTES);
    match secretbox::open_detached(
        &mut header_body_buf,
        &secretbox::Tag::from_slice(&header_tag_buf).unwrap(),
        &key_nonce.nonce,
        &key_nonce.key,
    ) {
        Ok(()) => {
            key_nonce.increment_nonce_be_inplace();
            Ok(Header::from_slice(&header_body_buf).unwrap())
        }
        Err(()) => Err(Error::DecryptHeaderSecretbox),
    }
}

/// Decrypt the body of a boxstream message from `buf` inplace.  Returns the number of bytes of the
/// decrypted body in `buf`.
fn decrypt_box_stream_body(
    header: &Header,
    key_nonce: &mut KeyNonce,
    buf: &mut [u8],
) -> Result<usize> {
    let mut body_buf = &mut buf[..header.body_len];
    match secretbox::open_detached(
        &mut body_buf,
        &header.body_mac,
        &key_nonce.nonce,
        &key_nonce.key,
    ) {
        Ok(()) => {
            key_nonce.increment_nonce_be_inplace();
            Ok(header.body_len)
        }
        Err(()) => Err(Error::DecryptBodySecretbox),
    }
}

/// The state of a boxstream receiver.  It can be expecting a header or the body of a previously
/// received header.
#[derive(Debug)]
enum RecvState {
    ExpectHeader,
    ExpectBody(Header),
}

/// The transport agnostic boxstream receiving side.
pub struct BoxStreamRecv {
    key_nonce: KeyNonce,
    state: RecvState,
}

// TODO: Handle goodbye
impl BoxStreamRecv {
    /// Create a new `BoxStreamRecv` from the `key_nonce`.
    pub fn new(key_nonce: KeyNonce) -> Self {
        Self {
            key_nonce,
            state: RecvState::ExpectHeader,
        }
    }
    /// Decrypt a single boxstream message every two calls (one to decrypt and parse the header, the
    /// other do decrypt the body) by decrypting from `buf` and writting the plaintex into `dec`.
    /// Returns the number of bytes read from `buf` and the number of bytes written into `dec`.
    pub fn decrypt(&mut self, buf: &[u8], dec: &mut [u8]) -> Result<(usize, usize)> {
        // NOTE: Maybe this check should be removed because reading 0 bytes can be understood as
        // EOF in a Read trait api.
        let n = self.recv_bytes();
        if buf.len() < n {
            return Ok((0, 0));
        }
        let mut state = RecvState::ExpectHeader;
        mem::swap(&mut state, &mut self.state);
        match state {
            RecvState::ExpectHeader => {
                dec[..n].copy_from_slice(&buf[..n]);
                let header = decrypt_box_stream_header(&mut self.key_nonce, &mut dec[..n])?;
                self.state = RecvState::ExpectBody(header);
                Ok((n, 0))
            }
            RecvState::ExpectBody(header) => {
                dec[..n].copy_from_slice(&buf[..n]);
                assert_eq!(
                    n,
                    decrypt_box_stream_body(&header, &mut self.key_nonce, &mut dec[..n],)?
                );
                self.state = RecvState::ExpectHeader;
                Ok((n, n))
            }
        }
    }

    /// Returns the number of received bytes needed for the next `decrypt` call.
    pub fn recv_bytes(&self) -> usize {
        match &self.state {
            RecvState::ExpectHeader => MSG_HEADER_LEN,
            RecvState::ExpectBody(header) => header.body_len,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A_HEX: &str = "8198e2d3456f022b2020f36ce874ad8b337a1c2da13f69f6458fd63415a51943";
    const NONCE_A_HEX: &str = "a20fa8fe59a80f5f07c80265e5e7664582f0f553f36cd6ce";
    const KEY_B_HEX: &str = "9bf1ec7af3f80934474e5ff73e27f2f5070f4fe4d80511923b7acb686463bfcc";
    const NONCE_B_HEX: &str = "799762378d9e1d0a8a510a249dc4e76788d6ff9993efc5df";

    #[test]
    fn test_keynonce() {
        const KEY_HEX: &str = "8198e2d3456f022b2020f36ce874ad8b337a1c2da13f69f6458fd63415a51943";
        const NONCE0_HEX: &str = "00000000000000000000000000000000000000000a00ffff";
        const NONCE1_HEX: &str = "00000000000000000000000000000000000000000a010000";
        let key = secretbox::Key::from_slice(&hex::decode(KEY_HEX).unwrap()).unwrap();
        let nonce0 = secretbox::Nonce::from_slice(&hex::decode(NONCE0_HEX).unwrap()).unwrap();
        let nonce1 = secretbox::Nonce::from_slice(&hex::decode(NONCE1_HEX).unwrap()).unwrap();
        let mut key_nonce = KeyNonce { key, nonce: nonce0 };
        key_nonce.increment_nonce_be_inplace();
        assert_eq!(key_nonce.nonce, nonce1);
    }

    struct Peer {
        key_nonce_send: KeyNonce,
        key_nonce_recv: KeyNonce,
    }

    fn load_peers() -> (Peer, Peer) {
        let key_a = secretbox::Key::from_slice(&hex::decode(KEY_A_HEX).unwrap()).unwrap();
        let nonce_a = secretbox::Nonce::from_slice(&hex::decode(NONCE_A_HEX).unwrap()).unwrap();
        let key_b = secretbox::Key::from_slice(&hex::decode(KEY_B_HEX).unwrap()).unwrap();
        let nonce_b = secretbox::Nonce::from_slice(&hex::decode(NONCE_B_HEX).unwrap()).unwrap();

        let peer_a = Peer {
            key_nonce_send: KeyNonce {
                key: key_a.clone(),
                nonce: nonce_a,
            },
            key_nonce_recv: KeyNonce {
                key: key_b.clone(),
                nonce: nonce_b,
            },
        };
        let peer_b = Peer {
            key_nonce_send: KeyNonce {
                key: key_b.clone(),
                nonce: nonce_b,
            },
            key_nonce_recv: KeyNonce {
                key: key_a.clone(),
                nonce: nonce_a,
            },
        };
        (peer_a, peer_b)
    }

    #[test]
    fn test_boxstream() {
        let (mut peer_a, mut peer_b) = load_peers();

        let mut buf_a = [0; 4096];
        let mut buf_b = [0; 4096];

        let msg_a0: Vec<u8> = (0..=255).collect();
        let msg_a1: Vec<u8> = (0..=255).rev().collect();
        let msg_a2: Vec<u8> = (0..=255).collect();

        // Send two messages from A to B
        for msg_a in &[msg_a0, msg_a1, msg_a2] {
            // A
            let send_buf_a = {
                let (n_read, n_write) =
                    encrypt_box_stream_msg(&mut peer_a.key_nonce_send, &msg_a, &mut buf_a);
                // Assert that 256 bytes have been encrypted from msg_a
                assert_eq!(n_read, 256);
                &buf_a[..n_write]
            };

            // B
            let mut recv_buf_b = &mut buf_b[..send_buf_a.len()];
            recv_buf_b.copy_from_slice(send_buf_a);
            let dec_msg_a = {
                let header =
                    decrypt_box_stream_header(&mut peer_b.key_nonce_recv, &mut recv_buf_b).unwrap();
                // Assert that the body is 256 bytes
                assert_eq!(header.body_len, 256);
                let mut enc_body = &mut recv_buf_b[MSG_HEADER_LEN..];
                let n = decrypt_box_stream_body(&header, &mut peer_b.key_nonce_recv, &mut enc_body)
                    .unwrap();
                // Assert that the decrypted bytes are all the received bytes
                assert_eq!(n, enc_body.len());
                &enc_body[..n]
            };
            // Assert that the decrypted message is the message that was encrypted
            assert_eq!(&dec_msg_a[..], &msg_a[..]);
        }
    }

    #[test]
    fn test_boxstream_send_recv() {
        let (peer_a, peer_b) = load_peers();

        let mut sender = BoxStreamSend::new(peer_a.key_nonce_send);
        let mut receiver = BoxStreamRecv::new(peer_b.key_nonce_recv);

        let mut buf_a = [0; 4096];
        let mut buf_b = [0; 4096];

        let msg_a0: Vec<u8> = (0..=255).collect();
        let msg_a1: Vec<u8> = (0..=255).rev().collect();
        let msg_a2: Vec<u8> = (0..=255).collect();

        // Send two messages from A to B
        for msg_a in &[msg_a0, msg_a1, msg_a2] {
            // A
            let send_buf_a = {
                let (n_read, n_write) = sender.encrypt(&msg_a, &mut buf_a);
                // Assert that 256 bytes have been encrypted from msg_a
                assert_eq!(n_read, 256);
                assert_eq!(n_write, MSG_HEADER_LEN + 256);
                &buf_a[..n_write]
            };

            let mut recv_buf_a = send_buf_a;

            // B
            let dec_msg_a = {
                // Decrypt header
                let (n_read, n_write) = receiver.decrypt(&recv_buf_a, &mut buf_b).unwrap();
                assert_eq!(n_read, MSG_HEADER_LEN);
                assert_eq!(n_write, 0);
                recv_buf_a = &recv_buf_a[n_read..];
                // Decrypt body
                let (n_read, n_write) = receiver.decrypt(&recv_buf_a, &mut buf_b).unwrap();
                assert_eq!(n_read, 256);
                assert_eq!(n_write, 256);
                &buf_b[..n_write]
            };
            // Assert that the decrypted message is the message that was encrypted
            assert_eq!(&dec_msg_a[..], &msg_a[..]);
        }
    }
}
