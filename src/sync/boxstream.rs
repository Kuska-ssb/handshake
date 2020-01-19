use std::{convert, io, io::Read, io::Write};

use crate::boxstream::{
    self, BoxStreamRecv, BoxStreamSend, KeyNonce, MSG_BODY_MAX_LEN, MSG_HEADER_LEN,
};
use crate::handshake::HandshakeComplete;

impl std::error::Error for boxstream::Error {}

impl convert::From<boxstream::Error> for io::Error {
    fn from(error: boxstream::Error) -> Self {
        match error {
            boxstream::Error::DecryptHeaderSecretbox => {
                Self::new(io::ErrorKind::InvalidInput, error)
            }
            boxstream::Error::DecryptBodySecretbox => Self::new(io::ErrorKind::InvalidInput, error),
        }
    }
}

pub struct BoxStreamRead<R> {
    stream: R,
    bs_recv: BoxStreamRecv,
}

impl<R: Read> Read for BoxStreamRead<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut enc = [0; MSG_HEADER_LEN + MSG_BODY_MAX_LEN];
        let mut n = 0;
        for _ in 0..2 {
            let recv_bytes = self.bs_recv.recv_bytes();
            self.stream.read_exact(&mut enc[..recv_bytes])?;
            let (_, m) = self.bs_recv.decrypt(&enc[..recv_bytes], buf)?;
            n += m;
        }
        Ok(n)
    }
}

pub struct BoxStreamWrite<W> {
    stream: W,
    bs_send: BoxStreamSend,
}

impl<W: Write> Write for BoxStreamWrite<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut enc = [0; MSG_HEADER_LEN + MSG_BODY_MAX_LEN];
        let (n, m) = self.bs_send.encrypt(buf, &mut enc);
        self.stream.write_all(&enc[..m])?;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
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
        key_nonce_send: KeyNonce,
        key_nonce_recv: KeyNonce,
    ) -> Self {
        Self {
            reader: BoxStreamRead {
                stream: read_stream,
                bs_recv: BoxStreamRecv::new(key_nonce_recv),
            },
            writer: BoxStreamWrite {
                stream: write_stream,
                bs_send: BoxStreamSend::new(key_nonce_send),
            },
        }
    }

    pub fn from_handshake(
        read_stream: R,
        write_stream: W,
        handshake_complete: HandshakeComplete,
    ) -> Self {
        let (key_nonce_send, key_nonce_recv) = KeyNonce::from_handshake(handshake_complete);
        Self::new(read_stream, write_stream, key_nonce_send, key_nonce_recv)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::io::{Read, Write};

    use test_utils::net_sync::{net, net_fragment};

    use crossbeam::thread;
    use sodiumoxide::crypto::secretbox;

    const KEY_A_HEX: &str = "8198e2d3456f022b2020f36ce874ad8b337a1c2da13f69f6458fd63415a51943";
    const NONCE_A_HEX: &str = "a20fa8fe59a80f5f07c80265e5e7664582f0f553f36cd6ce";
    const KEY_B_HEX: &str = "9bf1ec7af3f80934474e5ff73e27f2f5070f4fe4d80511923b7acb686463bfcc";
    const NONCE_B_HEX: &str = "799762378d9e1d0a8a510a249dc4e76788d6ff9993efc5df";

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
            key_nonce_send: KeyNonce::new(key_a.clone(), nonce_a),
            key_nonce_recv: KeyNonce::new(key_b.clone(), nonce_b),
        };
        let peer_b = Peer {
            key_nonce_send: KeyNonce::new(key_b.clone(), nonce_b),
            key_nonce_recv: KeyNonce::new(key_a.clone(), nonce_a),
        };
        (peer_a, peer_b)
    }

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
                peer_a.key_nonce_send,
                peer_a.key_nonce_recv,
            );
            let (mut bs_a_read, _) = bs_a.split_read_write();

            let bs_b = BoxStream::new(
                stream_b_read,
                stream_b_write,
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
