extern crate log;
extern crate sodiumoxide;

use crate::asynchandshake::SharedSecret;
use log::debug;
use crate::buffer::CircularBuffer;
use sodiumoxide::crypto::{auth, hash::sha256, scalarmult::curve25519, secretbox, sign::ed25519};
use std::{cmp}; //, pin::Pin};
use async_std::{
    prelude::*,
    pin::Pin,
    task::{Context,Poll},
    io::{Read,Write,Result,Error,ErrorKind,self}
};

// Length of encrypted body (with MAC detached)
pub const MSG_BODY_MAX_LEN: usize = 4096;
// Length of decrypted header (body_len || enc_body_mac)
pub const MSG_HEADER_DEC_LEN: usize = 18;
// Length of encrypted header (with MAC prefixed)
pub const MSG_HEADER_LEN: usize = MSG_HEADER_DEC_LEN + secretbox::MACBYTES;

const GOODBYE : [u8;18] = [0u8;18];

pub struct KeyNonce {
    key: secretbox::Key,
    nonce: secretbox::Nonce,
}

enum MsgType<'a> {
    Body(&'a [u8]),
    Goodbye,
}

impl KeyNonce {
    pub fn increment_be_inplace(&mut self) {
        let mut byte_no : i8 = (self.nonce.0.len() - 1) as i8;
        while byte_no >= 0 {
            let (inc,_) = self.nonce.0[byte_no as usize].overflowing_add(1);
            self.nonce.0[byte_no as usize]=inc;
            if self.nonce.0[byte_no as usize] > 0 {
                return;
            }
            byte_no-=1;
        }
    }
}

enum HeaderType {
    Body(Header),
    Goodbye,
}


#[derive(Debug)]
pub struct Header {
    body_len: usize,
    body_mac: [u8; secretbox::MACBYTES],
}

impl Header {
    pub fn from_bytes(buf: &[u8; MSG_HEADER_DEC_LEN]) -> Self {
        Self {
            body_len: u16::from_be_bytes(*array_ref![buf[..2], 0, 2]) as usize,
            body_mac: *array_ref![buf[2..], 0, 16],
        }
    }

    pub fn to_bytes(&self) -> [u8; MSG_HEADER_DEC_LEN] {
        let buf = [
            (self.body_len as u16).to_be_bytes().as_ref(),
            self.body_mac.as_ref(),
        ]
        .concat();
        *array_ref![buf, 0, 18]
    }
}

pub struct AsyncBoxStream<R:Read, W:Write> {
    reader: AsyncBoxStreamRead<R>,
    writer: AsyncBoxStreamWrite<W>,
}

pub struct AsyncBoxStreamRead<R> {
    stream: R,
    key_nonce: KeyNonce,
    plain  : Box<[u8]>,
    plain_len : usize,
    plain_off : usize,
    cipher: Box<[u8]>,
    cipher_len : usize,
    status :  RecvStatus,
    read_limit : usize,
}

#[derive(Debug,PartialEq)]
pub enum Status {
    Open,
    Closing,
    Closed,
}

pub struct AsyncBoxStreamWrite<W> {
    stream: W,
    key_nonce: KeyNonce,
    cipher: CircularBuffer,
    plain: Box<[u8]>,
    plain_len : usize,
    goodbye_off : usize, // how many goodbye bytes are aready sent
    status : Status,
}

impl<R:Read+Unpin, W:Write+Unpin> AsyncBoxStream<R, W> {
    pub fn new(
        read_stream: R,
        write_stream: W,
        recv_buf_len: usize,
        net_id: auth::Key,
        pk: ed25519::PublicKey,
        ephemeral_pk: curve25519::GroupElement,
        peer_pk: ed25519::PublicKey,
        peer_ephemeral_pk: curve25519::GroupElement,
        shared_secret: SharedSecret,
    ) -> Self {
        let shared_secret_0 = sha256::hash(
            &[
                net_id.as_ref(),
                shared_secret.ab.as_ref(),
                shared_secret.aB.as_ref(),
                shared_secret.Ab.as_ref(),
            ]
            .concat(),
        );
        let shared_secret_1 = sha256::hash(shared_secret_0.as_ref());
        let send_hmac_nonce = auth::authenticate(peer_ephemeral_pk.as_ref(), &net_id);
        let send_key_nonce = KeyNonce {
            key: secretbox::Key(
                sha256::hash(&[shared_secret_1.as_ref(), peer_pk.as_ref()].concat()).0,
            ),
            nonce: secretbox::Nonce(*array_ref![send_hmac_nonce.as_ref(), 0, 24]),
        };
        let recv_hmac_nonce = auth::authenticate(ephemeral_pk.as_ref(), &net_id);
        let recv_key_nonce = KeyNonce {
            key: secretbox::Key(sha256::hash(&[shared_secret_1.as_ref(), pk.as_ref()].concat()).0),
            nonce: secretbox::Nonce(*array_ref![recv_hmac_nonce.as_ref(), 0, 24]),
        };
        let capacity = cmp::max(MSG_HEADER_LEN + MSG_BODY_MAX_LEN, recv_buf_len);
        debug!(
            "  recv_key_nonce.key {}",
            hex::encode(recv_key_nonce.key.as_ref())
        );
        debug!(
            "  recv_key_nonce.nonce {}",
            hex::encode(recv_key_nonce.nonce.as_ref())
        );
        debug!(
            "  send_key_nonce.key {}",
            hex::encode(send_key_nonce.key.as_ref())
        );
        debug!(
            "  send_key_nonce.nonce {}",
            hex::encode(send_key_nonce.nonce.as_ref())
        );
        Self {
            reader : AsyncBoxStreamRead::new(read_stream, recv_key_nonce, capacity),
            writer : AsyncBoxStreamWrite::new(write_stream, send_key_nonce, capacity),
        }
    }
}


impl<R:Read, W:Write> AsyncBoxStream<R, W> {
    pub fn split_read_write(self) -> (AsyncBoxStreamRead<R>, AsyncBoxStreamWrite<W>) {
        let AsyncBoxStream { reader, writer } = self;
        (reader, writer)
    }
}

#[derive(Debug)]
enum RecvStatus {
    ExpectHeader,
    ExpectBody(Header),
}

impl<R> AsyncBoxStreamRead<R> 
where
    R : Read+Unpin
{
    pub fn new(stream: R, key_nonce : KeyNonce, capacity: usize) -> AsyncBoxStreamRead<R> {
        Self {
            stream: stream,
            key_nonce: key_nonce,
            plain: vec![0; capacity].into_boxed_slice(),
            plain_len : 0,
            plain_off : 0,
            cipher: vec![0; capacity].into_boxed_slice(),
            cipher_len : 0,
            status : RecvStatus::ExpectHeader,
            read_limit : MSG_HEADER_LEN,    
        }
    }
}

impl<R> Read for AsyncBoxStreamRead<R>
where
    R : Read+Unpin
{
    fn poll_read( self: Pin<&mut Self>, cx:&mut Context, buf :&mut [u8] ) -> Poll<Result<usize>> {

        debug!("poll_read {}",buf.len());

        let this = self.get_mut();

        // if there's no data pending to read from deciphered text, read from underlying reader
        if this.plain_off == this.plain_len {

            // read up to read_limit
            let polled_read = Pin::new(&mut this.stream)
                .poll_read(cx,&mut this.cipher[this.cipher_len..this.read_limit]);
            let data_readed_len = futures::ready!(polled_read)?;

            debug!("  poll_read data_readed {}",data_readed_len);

            // check if the underlying stream is EOF
            if data_readed_len == 0 {
                return Poll::Ready(Ok(0));
            }

            this.cipher_len += data_readed_len;

            // it there's not enough for filling the buffer return pending
            // it is supposed that another poll_read is will be triggered, and this will 
            //   call this stream.poll_read and cx is going to attach to the underlying reader 
            if this.cipher_len < this.read_limit {
                return Poll::Pending;
            }

            match this.status {
                // Waiting for the header
                RecvStatus::ExpectHeader => {
                    debug!("  poll_read expect_header");
                    let header = decrypt_box_stream_header(
                        &mut this.key_nonce,
                        &mut this.cipher[..this.cipher_len],
                    )?;
                    match header {
                        HeaderType::Body(header) => {
                            if header.body_len > this.cipher.len() {
                                return Poll::Ready(Err(Error::new(ErrorKind::Other, "internal buffer too small")));
                            }
                            this.read_limit = MSG_HEADER_LEN + header.body_len;
                            debug!("  poll_read header_complete body_len={}",header.body_len);
                            this.status = RecvStatus::ExpectBody(header);
                            return Poll::Pending;        
                        } 
                        HeaderType::Goodbye => {
                            debug!("   poll_read goodbye recieved");
                            return Poll::Ready(Ok(0))
                        }
                    }
                }
                // Waiting for the body
                RecvStatus::ExpectBody(ref header) => {
                    debug!("  poll_read expect_body");
                    this.plain_len = decrypt_box_stream_body(
                        header,
                        &mut this.key_nonce,
                        &mut this.cipher[MSG_HEADER_LEN..this.read_limit],
                        &mut this.plain[..header.body_len],
                    )?;
                    debug!("  poll_read decipher_complete body_len={}",header.body_len);
                    this.plain_off = 0;
                }
            }
        }

        // copy data from plaintext buffer
        let len = cmp::min(this.plain_len-this.plain_off,buf.len());
        buf[..len].copy_from_slice(&this.plain[this.plain_off..this.plain_off+len]);
        this.plain_off += len;

        debug!("  poll_read reading_deciphered_buffer req {} got {}",buf.len(),len);
        debug!("    plain_off={} plain_len={}",this.plain_off, this.plain_len);

        // if all data has been readed, prepare to read next header
        if this.plain_off == this.plain_len  {
            debug!("    *reset");
            this.status = RecvStatus::ExpectHeader;
            this.read_limit = MSG_HEADER_LEN;
            this.plain_off = 0;
            this.plain_len = 0;
            this.cipher_len = 0;
        }

        Poll::Ready(Ok(len))
    }
}

pub struct CloseFuture<'a, W: Write + Unpin> {
    pub(crate) writer : &'a mut W,
}

impl<W: Write + Unpin> Future for CloseFuture<'_, W> {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let Self { writer } = &mut *self;
        futures::ready!(Pin::new(&mut *writer).poll_close(cx))?;
        Poll::Ready(Ok(()))
    }
}

impl<W> AsyncBoxStreamWrite<W>
where
    W : Write+Unpin
{
    pub fn new(stream: W, key_nonce : KeyNonce, capacity: usize) -> AsyncBoxStreamWrite<W> {
        Self {
            stream: stream,
            status : Status::Open,
            key_nonce: key_nonce,
            cipher: CircularBuffer::new(capacity),
            plain: vec![0; MSG_BODY_MAX_LEN].into_boxed_slice(),
            plain_len : 0,
            goodbye_off : 0,
        }
    }

    pub fn close<'a>(&'a mut self) -> CloseFuture<'a, Self> {
        CloseFuture { writer : self }
    }

    fn internal_flush(&mut self, cx: &mut Context) -> Poll<Result<()>> {

        // if there's pending data to cipher, cipher it into the cipher buffer
        if self.plain_len > 0 {

            debug!("  buffer_flush plain_len {}",self.plain_len);
            let mut tmp_cipher = Vec::with_capacity(MSG_HEADER_LEN + self.plain_len);    
            encrypt_box_stream_msg(&mut self.key_nonce, MsgType::Body(&self.plain[0..self.plain_len]), &mut tmp_cipher);
            match self.cipher.write_from(&mut &tmp_cipher[..]) {
                Err(err) => return Poll::Ready(Err(err)),
                _ => ()
            };
            debug!("  buffer_flush enc_write tmp_buf_len {}", tmp_cipher.len());
            debug!("  buffer_flush enc_write enc_len {}", self.cipher.len());
            self.plain_len = 0;
        }

        // flush all the cipher data 
        let n = futures::ready!(Pin::new(&mut self.stream).poll_write(cx,self.cipher.contiguous_value()))?;
        self.cipher.skip(n);
        if self.cipher.len() > 0 {
            // maybe there's more data to send in the second part of the circular buffer
            let n = futures::ready!(Pin::new(&mut self.stream).poll_write(cx,self.cipher.contiguous_value()))?;
            self.cipher.skip(n);
        }
        if self.cipher.len() > 0  {
            return Poll::Pending;
        }

        self.cipher.clear();
        Poll::Ready(Ok(()))
    }
    fn flush_pending(&self) -> bool {
        self.plain_len  > 0 || self.cipher.len() > 0
    }
}






impl<W> Write for AsyncBoxStreamWrite<W>
where
    W : Write+Unpin
 {
    // Attempt to write bytes from buf into the object.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8]
    ) -> Poll<Result<usize>> {

        debug!("poll_write buf_len={} {}",buf.len(),hex::encode(buf));

        let this = self.get_mut();

        if this.status != Status::Open {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected,"Connection closed")))
        }        

        let mut consumed_bytes = 0;

        // there's enough space in plaintext buffer fill it 
        if this.plain_len < MSG_BODY_MAX_LEN {
            consumed_bytes = cmp::min(MSG_BODY_MAX_LEN-this.plain_len,buf.len());
            &this.plain[this.plain_len..this.plain_len+consumed_bytes].copy_from_slice(&buf[..consumed_bytes]);
            this.plain_len += consumed_bytes;
            debug!("  buffer_write dec_write {} (buf_len={})",consumed_bytes,buf.len());
        }

        // there's a full packet of plaintext, try cipher it
        if this.plain_len == MSG_BODY_MAX_LEN {

            // check if there's enough space in to store a new ciphered packet in the output buffer
            if this.cipher.cap()-this.cipher.len() >= MSG_HEADER_LEN + MSG_BODY_MAX_LEN {

                // all ok, cipher it, and reset the plaintext buffer
                let mut tmp_cipher = Vec::with_capacity(MSG_HEADER_LEN + MSG_BODY_MAX_LEN);    
                encrypt_box_stream_msg(&mut this.key_nonce, MsgType::Body(&this.plain[0..MSG_BODY_MAX_LEN]), &mut tmp_cipher);
                match this.cipher.write_from(&mut &tmp_cipher[..]) {
                    Err(err) => return Poll::Ready(Err(err)),
                    _ => ()
                };
                this.plain_len = 0;
            }
        }

        debug!("  buffer_write consumed_bytes={}",consumed_bytes);

        // if there's some ciphertext to send to the writer, send to it
        //   only contiguos bytes in the circular buffer are sent, so in next 
        //   call will continue if the whole buffer is not drained

        if this.cipher.len() > 0 {            
            let polled_write = Pin::new(&mut this.stream)
                .poll_write(cx,this.cipher.contiguous_value());
            
            let n = futures::ready!(polled_write)?;
            this.cipher.skip(n);
        } 
        Poll::Ready(Ok(consumed_bytes))
    }

    // Attempt to flush the object, ensuring that any buffered data reach their destination.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        debug!("poll_flush ");

        let this = self.get_mut();

        if this.status != Status::Open {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected,"Connection closed")))
        }        

        futures::ready!(this.internal_flush(cx))?;
        Pin::new(&mut this.stream).poll_flush(cx)
    }
    
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {

        let this = self.get_mut();

        debug!("poll_close ");

        match this.status {
            Status::Closed => return Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected,"Already closed"))),
            Status::Open => this.status = Status::Closing,
            _ => {} ,
        }        

        // if there's pending data to flush, write them
        if this.flush_pending() {
            futures::ready!(this.internal_flush(cx))?;
        }

        // if there's pending goodbye bytes, write them
        if this.goodbye_off < MSG_HEADER_LEN {
            let mut tmp_cipher = Vec::with_capacity(MSG_HEADER_LEN);    
            encrypt_box_stream_msg(&mut this.key_nonce, MsgType::Goodbye, &mut tmp_cipher);
            let polled_write = Pin::new(&mut this.stream).poll_write(cx,&tmp_cipher[this.goodbye_off..]);
            this.goodbye_off += futures::ready!(polled_write)?;
            if this.goodbye_off < MSG_HEADER_LEN {
                return Poll::Pending 
            }
        }

        // close the underlying stream
        futures::ready!(Pin::new(&mut this.stream).poll_close(cx))?;

        // close box stream
        this.status = Status::Closed;

        debug!("   poll_close box goodbyte sent");
        Poll::Ready(Ok(()))
    }
}

// Encrypt a single message from buf into enc, return the number of bytes encryted from buf.
fn encrypt_box_stream_msg<'a>(key_nonce: &mut KeyNonce, msg: MsgType<'a>, enc: &mut Vec<u8>) -> usize {
    
    let header_nonce = key_nonce.nonce;
    key_nonce.increment_be_inplace();

    match msg {
        MsgType::Body(body) => {

            let body_nonce = key_nonce.nonce;
            key_nonce.increment_be_inplace();
            debug!(
                "encrypt header_nonce: {}",
                hex::encode(header_nonce.as_ref())
            );
            debug!("encrypt body_nonce: {}", hex::encode(body_nonce.as_ref()));
        
            let secret_body = secretbox::seal(body, &body_nonce, &key_nonce.key);
            let header = Header {
                body_len: body.len(),
                body_mac: *array_ref![secret_body, 0, secretbox::MACBYTES],
            };
            
            let secret_header = secretbox::seal(&header.to_bytes(), &header_nonce, &key_nonce.key);
            
            <Vec<u8> as std::io::Write>::write(enc,&secret_header).unwrap();
            <Vec<u8> as std::io::Write>::write(enc,&secret_body[secretbox::MACBYTES..]).unwrap();
            body.len()        
        }
        MsgType::Goodbye => {
            let secret_goodbye = secretbox::seal(&GOODBYE[..], &header_nonce, &key_nonce.key);
            <Vec<u8> as std::io::Write>::write(enc,&secret_goodbye).unwrap();
            0
        }
    }
}

fn decrypt_box_stream_header(key_nonce: &mut KeyNonce, buf: &[u8]) -> io::Result<HeaderType> {
    if buf.len() < MSG_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not enough bytes to read a header",
        ));
    }
    let secret_header = &buf[..MSG_HEADER_LEN];
    debug!("ready to decript encrypted header data: {}", hex::encode(&secret_header));
    match secretbox::open(secret_header, &key_nonce.nonce, &key_nonce.key) {
        Ok(h) => {
            key_nonce.increment_be_inplace();
            if h == GOODBYE {
                Ok(HeaderType::Goodbye)
            } else {
                Ok(HeaderType::Body(Header::from_bytes(array_ref![&h, 0, 18])))
            }
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
    buf: &[u8],
    dec: &mut [u8],
) -> io::Result<usize> {
    if buf.len() < header.body_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not enough bytes to read the body",
        ));
    }
    let secret_body = &[header.body_mac.as_ref(), &buf[..header.body_len]].concat();
    match secretbox::open(secret_body, &key_nonce.nonce, &key_nonce.key) {
        Ok(body) => {
            key_nonce.increment_be_inplace();
            dec[..header.body_len].copy_from_slice(&body);
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

mod test {
    use super::*;

    #[async_std::test]
    async fn check_asyncbox() -> io::Result<()> {

        let send_key_nonce = KeyNonce {
            key: secretbox::Key(sha256::hash(&[0]).0),
            nonce: secretbox::Nonce([0u8;24]),
        };
        let recv_key_nonce = KeyNonce {
            key: secretbox::Key(sha256::hash(&[0]).0),
            nonce: secretbox::Nonce([0u8;24]),
        };

        let stream = CircularBuffer::new(16384);
        let mut writer = AsyncBoxStreamWrite::new(stream,send_key_nonce,16384);
        
        writer.write_all(b"hola").await?;
        writer.write_all(b"antoni").await?;
        writer.write_all(&[7u8;5000]).await?;
        writer.write_all(&[8u8;5000]).await?;

        writer.flush().await?;
        
        let AsyncBoxStreamWrite { stream , .. } = writer;
        let mut reader = AsyncBoxStreamRead::new(stream,recv_key_nonce,16384);
        
        let mut holaantoni = [0u8;10];
        let mut sevens = [0u8;5000];
        let mut eights = [0u8;5000];

        reader.read_exact(&mut holaantoni[..]).await?;
        reader.read_exact(&mut sevens[..]).await?;
        reader.read_exact(&mut eights[..]).await?;
        
        assert_eq!(b"holaantoni",&holaantoni);
        assert_eq!(true,sevens.iter().all(|n| *n==7));
        assert_eq!(true,eights.iter().all(|n| *n==8));

        Ok(())
    }
}
