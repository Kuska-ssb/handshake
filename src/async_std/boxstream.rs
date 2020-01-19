use async_std::{
    io::{self, Error, ErrorKind, Read, Result, Write},
    pin::Pin,
    prelude::*,
    task::{Context, Poll},
};
use log::trace;
use std::cmp;

use crate::boxstream::{BoxStreamRecv, BoxStreamSend, KeyNonce, MSG_BODY_MAX_LEN};
use crate::handshake::HandshakeComplete;

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

    pub fn from_handshake(
        read_stream: R,
        write_stream: W,
        handshake_complete: HandshakeComplete,
        capacity: usize,
    ) -> Self {
        let (key_nonce_send, key_nonce_recv) = KeyNonce::from_handshake(handshake_complete);
        Self {
            reader: BoxStreamRead::new(read_stream, key_nonce_recv, capacity),
            writer: BoxStreamWrite::new(write_stream, key_nonce_send, capacity),
        }
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
        trace!("poll_read {}", buf.len());

        let this = self.get_mut();

        futures::ready!(assert_not_closed(&this.status))?;

        // if there's no data pending to read from deciphered text, read from underlying reader
        if this.plain_off == this.plain_len {
            trace!("  reset");

            // read up to cipher_len
            let polled_read = Pin::new(&mut this.stream)
                .poll_read(cx, &mut this.cipher[this.cipher_off..this.cipher_len]);
            let len = futures::ready!(polled_read)?;

            trace!("  ciphertext_readed={}", len);

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
                trace!("  needs {} more bytes to decipher", this.cipher_len - this.cipher_off);
                return Poll::Pending;
            }

            // all cipher data collected, decipher it
            // TODO(adria0) check if _readed matters here
            let (_readed, written) = this
                .bs_recv
                .decrypt(&this.cipher[..this.cipher_len], &mut this.plain[..])
                .map_err(|err| Error::new(ErrorKind::InvalidData, err))?;
            
            trace!("  deciphered_len={}", written);

            // update how much bytes the next ciphered chunk is
            this.cipher_off = 0;
            this.cipher_len = this.bs_recv.recv_bytes();

            trace!("  new cipher_len={}", this.cipher_len);

            // if recv_bytes is zero, we got a goodbye
            if this.cipher_len == 0 {
                trace!("  got goodbye");
                this.status = Status::Closed;
                return Poll::Ready(Ok(0));
            }

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

        trace!(
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
        trace!("  internal_flush()");

        // 1) first flush pending ciphered data
        if self.cipher_off < self.cipher_len {
            trace!(
                "    pending {} ciphered data to write",
                self.cipher_len - self.cipher_off
            );
            let n = futures::ready!(Pin::new(&mut self.stream)
                .poll_write(cx, &self.cipher[self.cipher_off..self.cipher_len]))?;
            self.cipher_off += n;

            trace!("      written {}", n);

            // no more data, can be written? wait underlying writer to
            //  be available
            if self.cipher_off < self.cipher_len {
                return Poll::Pending;
            }
        }

        // {inv : self.cipher_off == self.cipher_len  }

        // 2) if there's pending data to encrypt, cipher it
        if self.plain_off < self.plain_len {
            trace!(
                "    pending {} plain data to encrypt",
                self.plain_len - self.plain_off
            );

            let (read, written) = self.bs_send.encrypt(
                &self.plain[self.plain_off..self.plain_len],
                &mut self.cipher[..],
            );

            trace!("      ciphered #plain={} #encrypt={}", read, written);

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
        trace!("poll_write buf_len={}", buf.len());

        let this = self.get_mut();

        // check connection status
        futures::ready!(assert_not_closed(&this.status))?;

        // there's a full packet of plaintext, write it and flush pending
        if this.plain_len == MSG_BODY_MAX_LEN {
            trace!("  max_body_len_reached, flushing");
            futures::ready!(this.internal_flush(cx))?;

            // reset plaintext buffer
            this.plain_len = 0;
            this.plain_off = 0;
        }

        // write as much plaintext as possible
        let len = cmp::min(MSG_BODY_MAX_LEN - this.plain_len, buf.len());
        this.plain[this.plain_len..this.plain_len + len]
            .copy_from_slice(&buf[..len]);
        this.plain_len += len;
        trace!("  written {} bytes", len);

        Poll::Ready(Ok(len))
    }

    // Attempt to flush the object, ensuring that any buffered data reach their destination.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        trace!("poll_flush ");

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

        trace!("poll_close ");

        futures::ready!(assert_not_closed(&this.status))?;

        // flush pending
        futures::ready!(this.internal_flush(cx))?;

        if this.status == Status::Open {
            // fill again the cipher buffer and...
            this.status = Status::Closing;

            this.cipher_len = this.bs_send.encrypt_goodbye(&mut this.cipher[..]);
            this.cipher_off = 0;

            // force to re-call this function again
            cx.waker().clone().wake();
            return Poll::Pending;
        }

        // close the underlying stream
        futures::ready!(Pin::new(&mut this.stream).poll_close(cx))?;

        // close box stream
        this.status = Status::Closed;

        trace!("  goodbyte written");
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
    use super::*;
    use super::super::circularbuffer::CircularBuffer;
    use sodiumoxide::crypto::{hash::sha256, secretbox};

    #[async_std::test]
    async fn check_asyncbox1() -> io::Result<()> {
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
}
