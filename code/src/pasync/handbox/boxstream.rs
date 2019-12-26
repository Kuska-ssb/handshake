extern crate log;
extern crate sodiumoxide;

use log::debug;
use crate::boxstream::{BoxStreamSend, BoxStreamRecv, KeyNonce,MSG_BODY_MAX_LEN};
use crate::handshake::HandshakeComplete;

use async_std::{
    io::{self, Error, ErrorKind, Read, Result, Write},
    pin::Pin,
    prelude::*,
    task::{Context, Poll},
};
use std::cmp;


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

    cipher: Box<[u8]>,
    cipher_len: usize,
    cipher_off: usize,

    plain: Box<[u8]>,
    plain_len: usize,
    plain_off: usize,
}

pub struct BoxStreamRead<R> {
    stream: R,
    status: Status,
    bs_recv: BoxStreamRecv,

    // buffer for ciphertext data
    cipher: Box<[u8]>,
    cipher_len: usize,
    read_limit: usize,

    // buffer for plaintext data
    plain: Box<[u8]>,
    plain_len: usize,
    plain_off: usize,
}

impl<R: Read, W: Write> BoxStream<R, W> {
    pub fn split_read_write(self) -> (BoxStreamRead<R>, BoxStreamWrite<W>) {
        let BoxStream { reader, writer } = self;
        (reader, writer)
    }

    pub fn from_handhake(read_stream: R, write_stream: W, handshake_complete: HandshakeComplete, capacity: usize) -> Self {
        let (key_nonce_send, key_nonce_recv) = KeyNonce::from_handshake(handshake_complete);

        let bs_recv = BoxStreamRecv::new(key_nonce_recv);
        let bs_send = BoxStreamSend::new(key_nonce_send);

        let reader = BoxStreamRead {
            stream: read_stream,
            status: Status::Open,
            read_limit: bs_recv.recv_bytes(),

            plain: vec![0; capacity].into_boxed_slice(),
            plain_len: 0,
            plain_off: 0,
            cipher: vec![0; capacity].into_boxed_slice(),
            cipher_len: 0,

            bs_recv,
        };
        let writer = BoxStreamWrite {
            stream: write_stream,
            status: Status::Open,
            bs_send,
            cipher: vec![0; capacity].into_boxed_slice(),
            cipher_len: 0,
            cipher_off: 0,
            plain: vec![0; MSG_BODY_MAX_LEN].into_boxed_slice(),
            plain_len: 0,
            plain_off: 0,
        };

        Self { reader, writer }
    }

}

impl<R> BoxStreamRead<R>
where
    R: Read + Unpin,
{
    pub fn new(stream: R, key_nonce: KeyNonce, capacity: usize) -> BoxStreamRead<R> {
        let bs = BoxStreamRecv::new(key_nonce);
        Self {
            stream: stream,
            plain: vec![0; capacity].into_boxed_slice(),
            plain_len: 0,
            plain_off: 0,
            cipher: vec![0; capacity].into_boxed_slice(),
            cipher_len: 0,
            status: Status::Open,
            read_limit: bs.recv_bytes(),
            bs_recv: bs,
        }
    }
}

impl<R> Read for BoxStreamRead<R>
where
    R: Read + Unpin,
{
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8]) -> Poll<Result<usize>> {
        debug!("poll_read {}", buf.len());

        let this = self.get_mut();

        if this.read_limit == 0 {
            let unexpected_eof = Error::new(ErrorKind::UnexpectedEof, "EOF before GOODBYE");
            return Poll::Ready(Err(unexpected_eof));        
        }

        // if there's no data pending to read from deciphered text, read from underlying reader
        if this.plain_off == this.plain_len {

            debug!("  reset");

            // read up to read_limit
            let polled_read = Pin::new(&mut this.stream)
                .poll_read(cx, &mut this.cipher[this.cipher_len..this.read_limit]);
            let data_readed_len = futures::ready!(polled_read)?;

            debug!("  data_readed={}", data_readed_len);

            // check if the underlying stream is EOF
            if data_readed_len == 0 {
                // got an EOF before GOODBYE
                let not_connected = Error::new(ErrorKind::NotConnected, "EOF");
                return Poll::Ready(Err(not_connected));
            }

            this.cipher_len += data_readed_len;

            // it there's not enough for filling the buffer return pending
            if this.cipher_len < this.read_limit {
                debug!("  needs {} more bytes to decipher", this.read_limit - this.cipher_len);
                cx.waker().clone().wake();
                return Poll::Pending;
            }

            let (_readed,written) = this.bs_recv.decrypt( // TODO what to do with readed?
                &mut this.cipher[..this.read_limit],
                &mut this.plain[..],
            ).map_err(|err| Error::new(ErrorKind::InvalidData,err))?;
            
            debug!("  deciphered_len={}", written);

            // update how much bytes in len the next chunk is  
            this.cipher_len = 0;
            this.read_limit = this.bs_recv.recv_bytes();

            debug!("  new read_limit={}", this.read_limit);

            if this.read_limit == 0 {
                // got GOODBYE
                debug!("  got goodbye");
                this.status = Status::Closed;
                return Poll::Ready(Ok(0));
            }

            if written == 0 {
                // readed the headed, so time to read the body
                cx.waker().clone().wake();
                return Poll::Pending;
            }

            this.plain_off = 0;
            this.plain_len = written;
        }

        // copy data from plaintext buffer
        let len = cmp::min(this.plain_len - this.plain_off, buf.len());
        buf[..len].copy_from_slice(&this.plain[this.plain_off..this.plain_off + len]);
        this.plain_off += len;

        debug!(
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
            stream: stream,
            status: Status::Open,
            bs_send : super::boxstream::BoxStreamSend::new(key_nonce),
            cipher: vec![0; capacity].into_boxed_slice(),
            cipher_len: 0,
            cipher_off: 0,
            plain: vec![0; MSG_BODY_MAX_LEN].into_boxed_slice(),
            plain_len: 0,
            plain_off: 0,
        }
    }

    pub fn goodbye<'a>(&'a mut self) -> GoodbyeFuture<'a, Self> {
        GoodbyeFuture { writer: self }
    }

    fn internal_flush(&mut self, cx: &mut Context) -> Poll<Result<()>> {

        debug!("  internal_flush()");

        // 1) first flush pending ciphered data
        if self.cipher_off < self.cipher_len {
            debug!("    pending {} ciphered data to write", self.cipher_len - self.cipher_off);
            let n = futures::ready!(
                Pin::new(&mut self.stream).poll_write(cx, &self.cipher[self.cipher_off..self.cipher_len])
            )?;
            debug!("      written {}", n);
            self.cipher_off += n;

            if self.cipher_off < self.cipher_len {
                return Poll::Pending;                
            }
        }

        // 2) if there's pending data to cipher, cipher it
        if self.plain_off < self.plain_len {
            debug!("    pending {} plain data to cipher", self.plain_len - self.plain_off);
            let (read,written) = self.bs_send.encrypt(
                &self.plain[self.plain_off..self.plain_len],
                &mut self.cipher[..]
            );

            debug!("      ciphered #plain={} #cipher={}",read,written);

            self.plain_off += read;
            self.cipher_len = written;
            self.cipher_off = 0;

            // force the calling async operation to be called again (so, calls 1)
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
        debug!("poll_write buf_len={}", buf.len());

        let this = self.get_mut();

        // check connection status
        if this.status != Status::Open {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Connection closed",
            )));
        }

        // there's a full packet of plaintext, write it and flush pending
        if this.plain_len == MSG_BODY_MAX_LEN {
            debug!("  max_body_len_reached, flushing");
            futures::ready!(this.internal_flush(cx))?;
            this.plain_len = 0;
            this.plain_off = 0;
        }

        // there's enough space in plaintext buffer fill it
        let consumed_bytes = cmp::min(MSG_BODY_MAX_LEN - this.plain_len, buf.len());
        &this.plain[this.plain_len..this.plain_len + consumed_bytes]
            .copy_from_slice(&buf[..consumed_bytes]);
        this.plain_len += consumed_bytes;
        debug!(
            "  consumed {} bytes",
            consumed_bytes
        );

        Poll::Ready(Ok(consumed_bytes))
    }

    // Attempt to flush the object, ensuring that any buffered data reach their destination.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        debug!("poll_flush ");

        let this = self.get_mut();

        if this.status != Status::Open {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Connection closed",
            )));
        }

        futures::ready!(this.internal_flush(cx))?;
        Pin::new(&mut this.stream).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        let this = self.get_mut();

        debug!("poll_close ");

        if this.status ==  Status::Closed { 
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "Already closed",
            )))
        }

        // flush pending
        futures::ready!(this.internal_flush(cx))?;

        if this.status == Status::Open {
            // fill again the cipher buffer and force to
            //   re-call this function             
            this.status = Status::Closing;

            this.cipher_len = this.bs_send.encrypt_goodbye(&mut this.cipher[..]);
            this.cipher_off = 0;

            cx.waker().clone().wake();
            return Poll::Pending;            
        }

        // close the underlying stream
        futures::ready!(Pin::new(&mut this.stream).poll_close(cx))?;

        // close box stream
        this.status = Status::Closed;

        debug!("  goodbyte written");
        Poll::Ready(Ok(()))
    }
}


mod test {
    use super::*;
    use sodiumoxide::crypto::{secretbox,hash::sha256};
    use crate::pasync::util::CircularBuffer;

    #[async_std::test]
    async fn check_asyncbox1() -> io::Result<()> {
        let send_key_nonce = KeyNonce::new(
            secretbox::Key(sha256::hash(&[0]).0),
            secretbox::Nonce([0u8; 24])
        );
        let recv_key_nonce = KeyNonce::new(
            secretbox::Key(sha256::hash(&[0]).0),
            secretbox::Nonce([0u8; 24])
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
