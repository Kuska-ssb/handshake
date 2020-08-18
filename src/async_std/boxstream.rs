use async_std::{
    io::{self, Error, ErrorKind, Read, Result, Write},
    pin::Pin,
    prelude::*,
    task::{Context, Poll},
};
use log::trace;
use std::cmp;

use crate::{
    boxstream::{BoxStreamRecv, BoxStreamSend, Decrypted, KeyNonce, MSG_BODY_MAX_LEN},
    handshake::HandshakeComplete,
};

#[derive(Debug, PartialEq)]
pub enum Status {
    Open,
    Closing,
    Closed,
}

pub struct BoxStream<R: Read, W: Write> {
    reader: BoxStreamRead<R>,
    writer: BoxStreamWrite<W>,
}

pub struct BoxStreamWrite<W> {
    stream: W,
    status: Status,
    bs_send: BoxStreamSend,

    // plaintext written, that becomes...
    plain: Box<[u8]>,
    plain_len: usize,
    plain_off: usize,

    // ciphertext to be writen in W
    cipher: Box<[u8]>,
    cipher_len: usize,
    cipher_off: usize,
}

pub struct BoxStreamRead<R> {
    stream: R,
    status: Status,
    bs_recv: BoxStreamRecv,

    // ciphertext readed from R, that becomes...
    cipher: Box<[u8]>,
    cipher_len: usize,
    cipher_off: usize,

    // plaintext to be readed
    plain: Box<[u8]>,
    plain_len: usize,
    plain_off: usize,
}

impl<R: Read + Unpin, W: Write + Unpin> BoxStream<R, W> {
    pub fn split_read_write(self) -> (BoxStreamRead<R>, BoxStreamWrite<W>) {
        let BoxStream { reader, writer } = self;
        (reader, writer)
    }

    pub fn new(
        read_stream: R,
        write_stream: W,
        key_nonce_send: KeyNonce,
        key_nonce_recv: KeyNonce,
        capacity: usize,
    ) -> Self {
        Self {
            reader: BoxStreamRead::new(read_stream, key_nonce_recv, capacity),
            writer: BoxStreamWrite::new(write_stream, key_nonce_send, capacity),
        }
    }

    pub fn from_handshake(
        read_stream: R,
        write_stream: W,
        handshake_complete: HandshakeComplete,
        capacity: usize,
    ) -> Self {
        let (key_nonce_send, key_nonce_recv) = KeyNonce::from_handshake(handshake_complete);
        Self::new(
            read_stream,
            write_stream,
            key_nonce_send,
            key_nonce_recv,
            capacity,
        )
    }
}

impl<R> BoxStreamRead<R>
where
    R: Read + Unpin,
{
    pub fn new(stream: R, key_nonce: KeyNonce, capacity: usize) -> BoxStreamRead<R> {
        let bs = BoxStreamRecv::new(key_nonce);
        Self {
            stream,
            plain: vec![0; capacity].into_boxed_slice(),
            plain_len: 0,
            plain_off: 0,
            cipher: vec![0; capacity].into_boxed_slice(),
            cipher_len: bs.recv_bytes(),
            cipher_off: 0,
            status: Status::Open,
            bs_recv: bs,
        }
    }
}

impl<R> Read for BoxStreamRead<R>
where
    R: Read + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8]) -> Poll<Result<usize>> {
        trace!(target:"ssb-handshake", "poll_read {}", buf.len());

        let this = self.get_mut();

        futures::ready!(assert_not_closed(&this.status))?;

        // if there's no data pending to read from deciphered text, read from underlying reader
        if this.plain_off == this.plain_len {
            trace!(target:"ssb-handshake","  reset");

            // read up to cipher_len
            let polled_read = Pin::new(&mut this.stream)
                .poll_read(cx, &mut this.cipher[this.cipher_off..this.cipher_len]);
            let len = futures::ready!(polled_read)?;

            trace!(target:"ssb-handshake","  ciphertext_readed={}", len);

            // check if the underlying stream is EOF
            if len == 0 {
                // got an EOF before GOODBYE
                let unexpected_eof = Error::new(ErrorKind::UnexpectedEof, "EOF before GOODBYE");
                return Poll::Ready(Err(unexpected_eof));
            }

            this.cipher_off += len;

            // it there's not enough for filling the buffer return pending
            //   waiting underlying write to wake
            if this.cipher_off < this.cipher_len {
                trace!(target:"ssb-handshake",
                    "  needs {} more bytes to decipher",
                    this.cipher_len - this.cipher_off
                );
                return Poll::Pending;
            }

            // all cipher data collected, decipher it
            // TODO(adria0) check if _readed matters here
            let (_readed, written) = match this
                .bs_recv
                .decrypt(&this.cipher[..this.cipher_len], &mut this.plain[..])?
            {
                Decrypted::Goodbye => {
                    trace!(target:"ssb-handshake","  got goodbye");
                    this.status = Status::Closed;
                    return Poll::Ready(Ok(0));
                }
                Decrypted::Some(v) => v,
            };

            trace!(target:"ssb-handshake","  deciphered_len={}", written);

            // update how much bytes the next ciphered chunk is
            this.cipher_off = 0;
            this.cipher_len = this.bs_recv.recv_bytes();

            trace!(target:"ssb-handshake","  new cipher_len={}", this.cipher_len);

            // if no data has been deciphered, it is only the header,
            //  do force to process the body
            if written == 0 {
                cx.waker().clone().wake();
                return Poll::Pending;
            }

            // prepare plain_buffer to be readed
            this.plain_off = 0;
            this.plain_len = written;
        }

        // { inv: this.plain_off < this.plain_len }
        // copy data from plaintext to user buffer
        let len = cmp::min(this.plain_len - this.plain_off, buf.len());
        buf[..len].copy_from_slice(&this.plain[this.plain_off..this.plain_off + len]);
        this.plain_off += len;

        trace!(target:"ssb-handshake",
            "  readed {} from deciphered buffer ({} requested)",
            len,
            buf.len()
        );

        Poll::Ready(Ok(len))
    }
}

pub struct GoodbyeFuture<'a, W: Write + Unpin> {
    pub(crate) writer: &'a mut W,
}

impl<W: Write + Unpin> Future for GoodbyeFuture<'_, W> {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self { writer } = &mut *self;
        futures::ready!(Pin::new(&mut *writer).poll_close(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl<W> BoxStreamWrite<W>
where
    W: Write + Unpin,
{
    pub fn new(stream: W, key_nonce: KeyNonce, capacity: usize) -> BoxStreamWrite<W> {
        Self {
            stream,
            status: Status::Open,
            bs_send: super::boxstream::BoxStreamSend::new(key_nonce),
            cipher: vec![0; capacity].into_boxed_slice(),
            cipher_len: 0,
            cipher_off: 0,
            plain: vec![0; MSG_BODY_MAX_LEN].into_boxed_slice(),
            plain_len: 0,
            plain_off: 0,
        }
    }

    /// send a GoodBye message
    pub fn goodbye(&mut self) -> GoodbyeFuture<'_, Self> {
        GoodbyeFuture { writer: self }
    }

    // flush all written data and send it into W
    fn internal_flush(&mut self, cx: &mut Context) -> Poll<Result<()>> {
        trace!(target:"ssb-handshake","  internal_flush()");

        // 1) first flush pending ciphered data
        if self.cipher_off < self.cipher_len {
            trace!(target:"ssb-handshake",
                "    pending {} ciphered data to write",
                self.cipher_len - self.cipher_off
            );
            let n = futures::ready!(Pin::new(&mut self.stream)
                .poll_write(cx, &self.cipher[self.cipher_off..self.cipher_len]))?;
            self.cipher_off += n;

            trace!(target:"ssb-handshake","      written {}", n);

            // no more data, can be written? wait underlying writer to
            //  be available
            if self.cipher_off < self.cipher_len {
                return Poll::Pending;
            }
        }

        // {inv : self.cipher_off == self.cipher_len  }

        // 2) if there's pending data to encrypt, cipher it
        if self.plain_off < self.plain_len {
            trace!(target:"ssb-handshake",
                "    pending {} plain data to encrypt",
                self.plain_len - self.plain_off
            );

            let (read, written) = self.bs_send.encrypt(
                &self.plain[self.plain_off..self.plain_len],
                &mut self.cipher[..],
            )?;

            trace!(target:"ssb-handshake","      ciphered #plain={} #encrypt={}", read, written);

            self.plain_off += read;

            // ciphertext is ready to be written, so
            self.cipher_len = written;
            self.cipher_off = 0;

            // force the calling async operation to be called again
            //   so, eventually calls 1

            cx.waker().clone().wake();
            return Poll::Pending;
        }

        Poll::Ready(Ok(()))
    }
}

impl<W> Write for BoxStreamWrite<W>
where
    W: Write + Unpin,
{
    // Attempt to write bytes from buf into the object.
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<Result<usize>> {
        trace!(target:"ssb-handshake","poll_write buf_len={}", buf.len());

        let this = self.get_mut();

        // check connection status
        futures::ready!(assert_not_closed(&this.status))?;

        // there's a full packet of plaintext, write it and flush pending
        if this.plain_len == MSG_BODY_MAX_LEN {
            trace!(target:"ssb-handshake","  max_body_len_reached, flushing");
            futures::ready!(this.internal_flush(cx))?;

            // reset plaintext buffer
            this.plain_len = 0;
            this.plain_off = 0;
        }

        // write as much plaintext as possible
        let len = cmp::min(MSG_BODY_MAX_LEN - this.plain_len, buf.len());
        this.plain[this.plain_len..this.plain_len + len].copy_from_slice(&buf[..len]);
        this.plain_len += len;
        trace!(target:"ssb-handshake","  written {} bytes", len);

        Poll::Ready(Ok(len))
    }

    // Attempt to flush the object, ensuring that any buffered data reach their destination.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        trace!(target:"ssb-handshake","poll_flush");

        let this = self.get_mut();
        futures::ready!(assert_not_closed(&this.status))?;

        // flush this stream
        futures::ready!(this.internal_flush(cx))?;

        // flush underlying stream
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    // Close the writer, flushing all pending data and sending the goodbye at the end.
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        let this = self.get_mut();

        trace!(target:"ssb-handshake","poll_close");

        futures::ready!(assert_not_closed(&this.status))?;

        // flush pending
        futures::ready!(this.internal_flush(cx))?;

        if this.status == Status::Open {
            // fill again the cipher buffer and...
            this.status = Status::Closing;

            this.cipher_len = this.bs_send.encrypt_goodbye(&mut this.cipher[..])?;
            this.cipher_off = 0;

            // force to re-call this function again
            cx.waker().clone().wake();
            return Poll::Pending;
        }

        // close the underlying stream
        futures::ready!(Pin::new(&mut this.stream).poll_close(cx))?;

        // close box stream
        this.status = Status::Closed;

        trace!(target:"ssb-handshake","  goodbyte written");
        Poll::Ready(Ok(()))
    }
}

fn assert_not_closed(actual: &Status) -> Poll<Result<()>> {
    if *actual == Status::Closed {
        return Poll::Ready(Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "Already closed",
        )));
    }
    Poll::Ready(Ok(()))
}

#[cfg(test)]
mod test {
    use super::{super::circularbuffer::CircularBuffer, *};
    use sodiumoxide::crypto::{hash::sha256, secretbox};

    #[async_std::test]
    async fn test_asyncbox() -> io::Result<()> {
        let send_key_nonce = KeyNonce::new(
            secretbox::Key(sha256::hash(&[0]).0),
            secretbox::Nonce([0u8; 24]),
        );
        let recv_key_nonce = KeyNonce::new(
            secretbox::Key(sha256::hash(&[0]).0),
            secretbox::Nonce([0u8; 24]),
        );

        let stream = CircularBuffer::new(16384);
        let mut writer = BoxStreamWrite::new(stream, send_key_nonce, 16384);
        writer.write_all(b"nice").await?;
        writer.write_all(b"ssbing").await?;
        writer.write_all(&[7u8; 5000]).await?;
        writer.write_all(&[8u8; 5001]).await?;
        writer.goodbye().await?;
        let BoxStreamWrite { stream, .. } = writer;
        let mut reader = BoxStreamRead::new(stream, recv_key_nonce, 16384);

        let mut nicessbing = [0u8; 10];
        let mut sevens = [0u8; 5000];
        let mut eights = [0u8; 5001];
        reader.read_exact(&mut nicessbing[..]).await?;
        reader.read_exact(&mut sevens[..]).await?;
        reader.read_exact(&mut eights[..]).await?;

        assert_eq!(b"nicessbing", &nicessbing);
        assert_eq!(true, sevens.iter().all(|n| *n == 7));
        assert_eq!(true, eights.iter().all(|n| *n == 8));

        let zero = reader.read(&mut nicessbing[..]).await?;
        assert_eq!(0, zero);

        Ok(())
    }

    use async_std::io::{Read, Write};
    use test_utils::net_async::{net, net_fragment};

    const CAPACITY: usize = 0x1010;

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

    #[async_std::test]
    async fn test_boxstream_async() {
        net(|a_rd, a_wr, b_rd, b_wr| boxstream_aux(a_rd, a_wr, b_rd, b_wr)).await;
    }

    #[async_std::test]
    async fn test_boxstream_async_fragment() {
        net_fragment(5, |a_rd, a_wr, b_rd, b_wr| {
            boxstream_aux(a_rd, a_wr, b_rd, b_wr)
        })
        .await;
    }

    async fn boxstream_aux_send<W: Write + Unpin>(
        mut bs_write: BoxStreamWrite<W>,
        msgs: Vec<Vec<u8>>,
    ) -> Result<()> {
        for msg in msgs {
            bs_write.write_all(&msg).await?;
            bs_write.flush().await?;
        }
        Ok(())
    }

    async fn boxstream_aux_recv<R: Read + Unpin>(
        mut bs_read: BoxStreamRead<R>,
        msgs: Vec<Vec<u8>>,
    ) -> Result<()> {
        for msg in &msgs {
            let mut buf = vec![0; msg.len()];
            bs_read.read_exact(&mut buf).await?;
            assert_eq!(&buf[..], &msg[..]);
        }
        Ok(())
    }

    // Send three messages from peer a to peer b in a boxstream
    async fn boxstream_aux<R: Read + Unpin, W: Write + Unpin>(
        stream_a_read: R,
        stream_a_write: W,
        stream_b_read: R,
        stream_b_write: W,
    ) {
        let (peer_a, peer_b) = load_peers();

        let msg_a0: Vec<u8> = (0..=255).collect();
        let msg_a1: Vec<u8> = (0..5000).map(|b| (b % 99) as u8).collect();
        let msg_a2: Vec<u8> = (0..=255).rev().collect();
        let msgs = vec![msg_a0, msg_a1, msg_a2];

        let bs_a = BoxStream::new(
            stream_a_read,
            stream_a_write,
            peer_a.key_nonce_send,
            peer_a.key_nonce_recv,
            CAPACITY,
        );
        let (bs_a_read, _) = bs_a.split_read_write();

        let bs_b = BoxStream::new(
            stream_b_read,
            stream_b_write,
            peer_b.key_nonce_send,
            peer_b.key_nonce_recv,
            CAPACITY,
        );
        let (_, bs_b_write) = bs_b.split_read_write();

        let future_recv = boxstream_aux_recv(bs_a_read, msgs.clone());
        let future_send = boxstream_aux_send(bs_b_write, msgs);

        let (recv, send) = future_recv.join(future_send).await;
        recv.unwrap();
        send.unwrap();
    }
}
