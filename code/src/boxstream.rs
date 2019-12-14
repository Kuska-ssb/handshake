extern crate log;
extern crate sodiumoxide;

use log::debug;

use crate::handshake::HandshakeComplete;

use sodiumoxide::crypto::{auth, hash::sha256, scalarmult::curve25519, secretbox};
use std::{cmp, io, io::Read, io::Write, mem};

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

impl KeyNonce {
    // Return (key_nonce_send, key_nonce_recv)
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
            nonce: secretbox::Nonce(*array_ref![send_hmac_nonce.as_ref(), 0, 24]),
        };
        let recv_hmac_nonce = auth::authenticate(ephemeral_pk.as_ref(), &net_id);
        let key_nonce_recv = KeyNonce {
            key: secretbox::Key(sha256::hash(&[shared_secret_1.as_ref(), pk.as_ref()].concat()).0),
            nonce: secretbox::Nonce::from_slice(&recv_hmac_nonce.as_ref()[..secretbox::NONCEBYTES])
                .unwrap(),
        };
        debug!(
            "key_nonce_recv.key {}",
            hex::encode(key_nonce_recv.key.as_ref())
        );
        debug!(
            "key_nonce_recv.nonce {}",
            hex::encode(key_nonce_recv.nonce.as_ref())
        );
        debug!(
            "key_nonce_send.key {}",
            hex::encode(key_nonce_send.key.as_ref())
        );
        debug!(
            "key_nonce_send.nonce {}",
            hex::encode(key_nonce_send.nonce.as_ref())
        );
        (key_nonce_send, key_nonce_recv)
    }

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

#[derive(Debug)]
pub struct Header {
    body_len: usize,
    body_mac: secretbox::Tag,
}

impl Header {
    pub fn from_bytes(buf: &[u8; MSG_HEADER_DEC_LEN]) -> Self {
        Self {
            body_len: u16::from_be_bytes([buf[0], buf[1]]) as usize,
            body_mac: secretbox::Tag::from_slice(&buf[2..]).unwrap(),
        }
    }

    pub fn from_slice(buf: &[u8]) -> Option<Self> {
        if buf.len() != MSG_HEADER_DEC_LEN {
            return None;
        }
        Some(Self {
            body_len: u16::from_be_bytes([buf[0], buf[1]]) as usize,
            body_mac: secretbox::Tag::from_slice(&buf[2..]).unwrap(),
        })
    }

    pub fn to_bytes(&self) -> [u8; MSG_HEADER_DEC_LEN] {
        concat!(
            MSG_HEADER_DEC_LEN,
            (self.body_len as u16).to_be_bytes().as_ref(),
            self.body_mac.as_ref()
        )
    }
}

// Encrypt a single message from buf into enc, return the number of bytes encryted from buf.
fn encrypt_box_stream_msg(key_nonce: &mut KeyNonce, buf: &[u8], enc: &mut [u8]) -> usize {
    let body = &buf[..cmp::min(buf.len(), MSG_BODY_MAX_LEN)];

    let header_nonce = key_nonce.nonce;
    key_nonce.increment_nonce_be_inplace();
    let body_nonce = key_nonce.nonce;
    key_nonce.increment_nonce_be_inplace();
    debug!(
        "encrypt header_nonce: {}",
        hex::encode(header_nonce.as_ref())
    );
    debug!("encrypt body_nonce: {}", hex::encode(body_nonce.as_ref()));

    let (header_buf, mut body_buf) =
        enc[..MSG_HEADER_LEN + body.len()].split_at_mut(MSG_HEADER_LEN);
    let (header_tag_buf, mut header_body_buf) = header_buf.split_at_mut(secretbox::MACBYTES);
    body_buf.copy_from_slice(body);
    let body_tag = secretbox::seal_detached(&mut body_buf, &body_nonce, &key_nonce.key);
    debug!(
        "write body ({}): {}, tag: {}",
        body_buf.len(),
        hex::encode(&body_buf),
        hex::encode(&body_tag)
    );
    let header = Header {
        body_len: body.len(),
        body_mac: body_tag,
    };
    header_body_buf.copy_from_slice(&header.to_bytes());
    let header_tag = secretbox::seal_detached(&mut header_body_buf, &header_nonce, &key_nonce.key);
    header_tag_buf.copy_from_slice(header_tag.as_ref());
    return body.len();
}

// Transport API agnostic boxstream sending side.
pub struct BoxStreamSend {
    key_nonce: KeyNonce,
}

impl BoxStreamSend {
    // Encrypt a single boxstream message by taking bytes from `buf` and encrypting them into
    // `enc`.  Returns the number of bytes read from `buf` and the number of bytes written to
    // `enc`.
    pub fn encrypt(&mut self, buf: &[u8], mut enc: &mut [u8]) -> (usize, usize) {
        let n = encrypt_box_stream_msg(&mut self.key_nonce, buf, &mut enc);
        (n, n + MSG_HEADER_LEN)
    }
}

fn decrypt_box_stream_header(key_nonce: &mut KeyNonce, buf: &mut [u8]) -> io::Result<Header> {
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
        Err(()) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secretbox::open for header failed",
            ));
        }
    }
}

fn decrypt_box_stream_body(
    header: &Header,
    key_nonce: &mut KeyNonce,
    buf: &mut [u8],
) -> io::Result<usize> {
    if buf.len() < header.body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not enough bytes to read the body",
        ));
    }
    let mut body_buf = &mut buf[..header.body_len];
    debug!(
        "read body ({}): {}, tag: {}",
        body_buf.len(),
        hex::encode(&body_buf),
        hex::encode(&header.body_mac)
    );
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
        Err(()) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "secretbox::open for body failed",
            ));
        }
    }
}

// Transport API agnostic boxstream receiving side.
pub struct BoxStreamRecv {
    key_nonce: KeyNonce,
    state: RecvState,
}

impl BoxStreamRecv {
    // Decrypt a single boxstream message every two calls (one to decrypt and parse the header, the
    // other do decrypt the body) by decrypting from `buf` and writting the plaintex to `dec`.
    // Returns the number of bytes read from `bud` and the number of bytes written to `dec`.
    pub fn decrypt(&mut self, buf: &[u8], dec: &mut [u8]) -> io::Result<(usize, usize)> {
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

    pub fn recv_bytes(&self) -> usize {
        match &self.state {
            RecvState::ExpectHeader => MSG_HEADER_LEN,
            RecvState::ExpectBody(header) => header.body_len,
        }
    }
}

pub struct BoxStream<R: Read, W: Write> {
    reader: BoxStreamRead<R>,
    writer: BoxStreamWrite<W>,
}

impl<R: Read, W: Write> BoxStream<R, W> {
    pub fn split_read_write(self) -> (BoxStreamRead<R>, BoxStreamWrite<W>) {
        let BoxStream { reader, writer } = self;
        (reader, writer)
    }

    pub fn new(
        read_stream: R,
        write_stream: W,
        recv_buf_len: usize,
        key_nonce_send: KeyNonce,
        key_nonce_recv: KeyNonce,
    ) -> Self {
        let capacity = cmp::max(MSG_HEADER_LEN + MSG_BODY_MAX_LEN, recv_buf_len);
        let reader = BoxStreamRead {
            stream: read_stream,
            key_nonce: key_nonce_recv,
            plain: vec![0; capacity].into_boxed_slice(),
            plain_len: 0,
            plain_off: 0,
            enc: vec![0; capacity].into_boxed_slice(),
            // buf: vec![0; capacity].into_boxed_slice(),
            // buf_cap: 0,
            // enc: vec![0; capacity].into_boxed_slice(),
            // enc_cap: 0,
            // dec: vec![0; capacity].into_boxed_slice(),
            // dec_pos: 0,
            // dec_cap: 0,
            // state: RecvState::ExpectHeader,
            // need_more_bytes: true,
        };
        let writer = BoxStreamWrite {
            stream: write_stream,
            key_nonce: key_nonce_send,
            // buf: Vec::with_capacity(MSG_BODY_MAX_LEN),
            // buf_cap: 0,
            // enc: Vec::with_capacity(capacity),
            enc: vec![0; capacity],
            // enc_pos: 0,
            // enc_cap: 0,
        };
        Self { reader, writer }
    }
}

#[derive(Debug)]
enum RecvState {
    ExpectHeader,
    ExpectBody(Header),
}

pub struct BoxStreamRead<R> {
    stream: R,
    key_nonce: KeyNonce,
    plain: Box<[u8]>,
    plain_len: usize,
    plain_off: usize,
    enc: Box<[u8]>,
    // buf: Box<[u8]>,
    // buf_cap: usize,
    // enc: Box<[u8]>,
    // enc_cap: usize,
    // dec: Box<[u8]>,
    // dec_pos: usize,
    // dec_cap: usize,
    // state: RecvState,
    // need_more_bytes: bool,
}

// NOTE: This read only handles one packet at a time.
// TODO: Add a test that sends two encrypted packets at once.
impl<R: Read> Read for BoxStreamRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // no data available, lock until available
        if self.plain_off == self.plain_len {
            let mut state = RecvState::ExpectHeader;
            let mut read_limit = MSG_HEADER_LEN;
            let mut enc_cap = 0;

            loop {
                enc_cap += self.stream.read(&mut self.enc[enc_cap..read_limit])?;
                if enc_cap < read_limit {
                    continue;
                }
                match state {
                    RecvState::ExpectHeader => {
                        debug!(
                            "read header ({}): {}",
                            self.enc[..read_limit].len(),
                            hex::encode(&self.enc[..read_limit])
                        );
                        let header = decrypt_box_stream_header(
                            &mut self.key_nonce,
                            &mut self.enc[..enc_cap],
                        )?;
                        if header.body_len > self.enc.len() {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                "internal buffer too small",
                            ));
                        }
                        read_limit = MSG_HEADER_LEN + header.body_len;
                        state = RecvState::ExpectBody(header);
                    }
                    RecvState::ExpectBody(ref header) => {
                        let n = cmp::min(header.body_len, read_limit - MSG_HEADER_LEN);
                        self.plain[..n]
                            .copy_from_slice(&self.enc[MSG_HEADER_LEN..MSG_HEADER_LEN + n]);
                        self.plain_len = decrypt_box_stream_body(
                            header,
                            &mut self.key_nonce,
                            &mut self.plain[..n],
                        )?;
                        self.plain_off = 0;
                        break;
                    }
                }
            }
        }

        // read from plaintext buffer
        let len = cmp::min(self.plain_len - self.plain_off, buf.len());
        buf[..len].copy_from_slice(&self.plain[self.plain_off..len]);
        self.plain_off += len;
        Ok(len)
    }
}

pub struct BoxStreamWrite<W> {
    stream: W,
    key_nonce: KeyNonce,
    // buf: Vec<u8>,
    // buf_cap: usize,
    enc: Vec<u8>,
    // enc_pos: usize,
    // enc_cap: usize,
}

impl<W: Write> Write for BoxStreamWrite<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Encrypt into as many messages as we can fit in the self.send.enc buffer
        let mut buf_n = 0;
        let mut enc_n = 0;
        while buf_n < buf.len() && enc_n + MSG_HEADER_LEN + MSG_BODY_MAX_LEN < self.enc.len() {
            let n =
                encrypt_box_stream_msg(&mut self.key_nonce, &buf[buf_n..], &mut self.enc[enc_n..]);
            buf_n += n;
            enc_n += n + MSG_HEADER_LEN;
            debug!("Encrypted {} bytes", n);
        }
        // Write all the encrypted messages to the stream
        self.stream.write_all(&self.enc[..enc_n])?;
        Ok(buf_n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
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
        let mut key_nonce = KeyNonce {
            key: key,
            nonce: nonce0,
        };
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

        // Send two messages from A to B
        for msg_a in &[msg_a0, msg_a1] {
            // A
            let send_buf_a = {
                let n = encrypt_box_stream_msg(&mut peer_a.key_nonce_send, &msg_a, &mut buf_a);
                // Assert that 256 bytes have been encrypted from msg_a
                assert_eq!(n, 256);
                &buf_a[..MSG_HEADER_LEN + n]
            };

            // B
            buf_b[..send_buf_a.len()].copy_from_slice(send_buf_a);
            let mut recv_buf_b = &mut buf_b[..send_buf_a.len()];
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

    use std::io::{Read, Write};

    use test_utils::{net, net_fragment};

    use crossbeam::thread;

    #[test]
    fn test_boxstream_sync() {
        net(|a_rd, a_wr, b_rd, b_wr| boxstream_aux(a_rd, a_wr, b_rd, b_wr));
    }

    #[test]
    fn test_boxstream_sync_fragment() {
        net_fragment(5, |a_rd, a_wr, b_rd, b_wr| {
            boxstream_aux(a_rd, a_wr, b_rd, b_wr)
        });
    }

    // Send two small messages from peer a to peer b in a boxstream
    fn boxstream_aux<R: Read + Send, W: Write + Send>(
        stream_a_read: R,
        stream_a_write: W,
        stream_b_read: R,
        stream_b_write: W,
    ) {
        let (peer_a, peer_b) = load_peers();

        let msg_a0: Vec<u8> = (0..=255).collect();
        let msg_a1: Vec<u8> = (0..5000).map(|b| (b % 99) as u8).collect();
        let msg_a2: Vec<u8> = (0..=255).rev().collect();
        let msg_a0_cpy = msg_a0.clone();
        let msg_a1_cpy = msg_a1.clone();
        let msg_a2_cpy = msg_a2.clone();

        thread::scope(|s| {
            let bs_a = BoxStream::new(
                stream_a_read,
                stream_a_write,
                0x8000,
                peer_a.key_nonce_send,
                peer_a.key_nonce_recv,
            );
            let (mut bs_a_read, _) = bs_a.split_read_write();

            let bs_b = BoxStream::new(
                stream_b_read,
                stream_b_write,
                0x8000,
                peer_b.key_nonce_send,
                peer_b.key_nonce_recv,
            );
            let (_, mut bs_b_write) = bs_b.split_read_write();

            let handle_a = s.spawn(move |_| {
                for msg in &[msg_a0_cpy, msg_a1_cpy, msg_a2_cpy] {
                    let mut buf = vec![0; msg.len()];
                    bs_a_read.read_exact(&mut buf).unwrap();
                    assert_eq!(&buf[..], &msg[..]);
                }
            });

            let handle_b = s.spawn(move |_| {
                for msg in &[msg_a0, msg_a1, msg_a2] {
                    bs_b_write.write_all(&msg).unwrap();
                    bs_b_write.flush().unwrap();
                }
            });

            handle_a.join().unwrap();
            handle_b.join().unwrap();
        })
        .unwrap();
    }
}
