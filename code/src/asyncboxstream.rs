extern crate log;
extern crate sodiumoxide;

use crate::handshake::SharedSecret;
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

pub struct KeyNonce {
    key: secretbox::Key,
    nonce: secretbox::Nonce,
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

pub struct BoxStreamRead<R> {
    stream: R,
    key_nonce: KeyNonce,
    dec  : Box<[u8]>,
    dec_len : usize,
    dec_off : usize,
    enc: Box<[u8]>,
    status :  RecvStatus,
    read_limit : usize,
    enc_cap : usize,
}

pub struct BoxStreamWrite<W> {
    stream: W,
    key_nonce: KeyNonce,
    enc: CircularBuffer,
    dec: Box<[u8]>,
    dec_len : usize,
}

pub struct BoxStream<R:Read, W:Write> {
    reader: BoxStreamRead<R>,
    writer: BoxStreamWrite<W>,
}


impl<R:Read, W:Write> BoxStream<R, W> {
    pub fn split_read_write(self) -> (BoxStreamRead<R>, BoxStreamWrite<W>) {
        let BoxStream { reader, writer } = self;
        (reader, writer)
    }
}

#[derive(Debug)]
enum RecvStatus {
    ExpectHeader,
    ExpectBody(Header),
}

impl<R> BoxStreamRead<R> 
where
    R : Read+Unpin
{
    pub fn new(stream: R, key_nonce : KeyNonce, capacity: usize) -> BoxStreamRead<R> {
        Self {
            stream: stream,
            key_nonce: key_nonce,
            dec: vec![0; capacity].into_boxed_slice(),
            dec_len : 0,
            dec_off : 0,
            enc: vec![0; capacity].into_boxed_slice(),
            enc_cap : 0,
            status : RecvStatus::ExpectHeader,
            read_limit : MSG_HEADER_LEN,    
        }
    }
}


impl<R> Read for BoxStreamRead<R>
where
    R : Read+Unpin
{
    fn poll_read( self: Pin<&mut Self>, cx:&mut Context,buf :&mut [u8] ) -> Poll<Result<usize>> {

        let BoxStreamRead {
            stream, key_nonce, enc, status, dec, read_limit, enc_cap, dec_off, dec_len, ..
        } = self.get_mut();

        if dec_off == dec_len {

            let poll = Pin::new(stream).poll_read(cx,&mut enc[*enc_cap..*read_limit]);
            match poll {
                Poll::Ready(Ok(n)) => {
                    *enc_cap += n;
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
            if enc_cap < read_limit {
                return Poll::Pending;
            }
            
            match status {
                RecvStatus::ExpectHeader => {
                    let header = decrypt_box_stream_header(
                        key_nonce,
                        &mut enc[..*enc_cap],
                    )?;
                    if header.body_len > enc.len() {
                        return Poll::Ready(Err(Error::new(ErrorKind::Other, "internal buffer too small")));
                    }
                    *read_limit = MSG_HEADER_LEN + header.body_len;
                    debug!("boxstream_reader_body_len={}",header.body_len);
                    *status = RecvStatus::ExpectBody(header);
                    return Poll::Pending;
                }
                RecvStatus::ExpectBody(ref header) => {
                    *dec_len = decrypt_box_stream_body(
                        header,
                        key_nonce,
                        &mut enc[MSG_HEADER_LEN..*read_limit],
                        &mut dec[..header.body_len],
                    )?;
                    *dec_off = 0;
                }
            }
        }

        // read from dectext buffer
        let len = cmp::min(*dec_len-*dec_off,buf.len());
        buf[..len].copy_from_slice(&dec[*dec_off..len]);
        *dec_off += len;
        Poll::Ready(Ok(len))
    }
}

impl<R:Read+Unpin, W:Write+Unpin> BoxStream<R, W> {
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
            "recv_key_nonce.key {}",
            hex::encode(recv_key_nonce.key.as_ref())
        );
        debug!(
            "recv_key_nonce.nonce {}",
            hex::encode(recv_key_nonce.nonce.as_ref())
        );
        debug!(
            "send_key_nonce.key {}",
            hex::encode(send_key_nonce.key.as_ref())
        );
        debug!(
            "send_key_nonce.nonce {}",
            hex::encode(send_key_nonce.nonce.as_ref())
        );
        Self {
            reader : BoxStreamRead::new(read_stream, recv_key_nonce, capacity),
            writer : BoxStreamWrite::new(write_stream, send_key_nonce, capacity),
        }
    }
}

impl<W> BoxStreamWrite<W>
where
    W : Write+Unpin
{
    pub fn new(stream: W, key_nonce : KeyNonce, capacity: usize) -> BoxStreamWrite<W> {
        Self {
            stream: stream,
            key_nonce: key_nonce,
            enc: CircularBuffer::new(capacity),
            dec: vec![0; capacity].into_boxed_slice(),
            dec_len : 0,
        }
    }
}

impl<W> Write for BoxStreamWrite<W>
where
    W : Write+Unpin
 {
    // Attempt to write bytes from buf into the object.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8]
    ) -> Poll<Result<usize>> {

        // Encrypt into as many messages as we can fit in the self.send.enc buffer
        let BoxStreamWrite { dec_len, dec, enc, key_nonce, stream, .. }
        = self.get_mut();

        let mut consumed_bytes = 0;

        if *dec_len < MSG_BODY_MAX_LEN {
            // there's enough space in plaintext buffer
            consumed_bytes = cmp::min(MSG_BODY_MAX_LEN-dec.len(),buf.len());
            &dec[*dec_len..*dec_len+consumed_bytes].copy_from_slice(&buf[..consumed_bytes]);
            *dec_len += consumed_bytes;
            debug!("buffer_write dec_write {}",consumed_bytes);
        }

        if *dec_len == MSG_BODY_MAX_LEN {
            debug!("buffer_write full packet");
            // there's a full packet to cipher
            if enc.cap()-enc.len() >= MSG_HEADER_LEN + MSG_BODY_MAX_LEN {
                // and also there's enough space in to store a new ciphered packet
                let mut tmp_enc = Vec::with_capacity(MSG_HEADER_LEN + MSG_BODY_MAX_LEN);    
                encrypt_box_stream_msg(key_nonce, &dec[0..*dec_len], &mut tmp_enc);
                match enc.write_from(&mut &tmp_enc[..]) {
                    Err(err) => return Poll::Ready(Err(err)),
                    _ => ()
                };
                debug!("buffer_write enc_write tmp_buf_len {}", tmp_enc.len());
                debug!("buffer_write enc_write enc_len {}", enc.len());
            }
        }

        let poll = Pin::new(stream).poll_write(cx,enc.contiguous_value());
        match poll {
            Poll::Ready(Ok(n)) => {
                debug!("buffer_write stream_write {}",n);
                enc.skip(n);
                Poll::Ready(Ok(consumed_bytes))
            },
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending,
        }

    }

    // Attempt to flush the object, ensuring that any buffered data reach their destination.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        
        let BoxStreamWrite { stream, enc, key_nonce, dec, dec_len, .. } = self.get_mut();

        if *dec_len > 0 {
            // cipher pending data
            debug!("buffer_flush dec_len {}",*dec_len);
            let mut tmp_enc = Vec::with_capacity(MSG_HEADER_LEN + *dec_len);    
            encrypt_box_stream_msg(key_nonce, &dec[0..*dec_len], &mut tmp_enc);
            match enc.write_from(&mut &tmp_enc[..]) {
                Err(err) => return Poll::Ready(Err(err)),
                _ => ()
            };
            debug!("buffer_flush enc_write tmp_buf_len {}", tmp_enc.len());
            debug!("buffer_flush enc_write enc_len {}", enc.len());
        }

        enc.defrag();
        debug!("buffer_flush stream_write_contiguous {}", enc.len());
        let poll = Pin::new(stream).poll_write(cx,enc.contiguous_value());
        match poll {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),  // what here if there's not enough??
            Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
            Poll::Pending => Poll::Pending
        }    
    }
    
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<()>> {
        let BoxStreamWrite { stream, .. } = self.get_mut();
        Pin::new(stream).poll_close(cx)
    }
}

// Encrypt a single message from buf into enc, return the number of bytes encryted from buf.
fn encrypt_box_stream_msg(key_nonce: &mut KeyNonce, buf: &[u8], enc: &mut Vec<u8>) -> usize {
    let body = &buf[..cmp::min(buf.len(), MSG_BODY_MAX_LEN)];

    let header_nonce = key_nonce.nonce;
    key_nonce.increment_be_inplace();
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
    return body.len();
}

fn decrypt_box_stream_header(key_nonce: &mut KeyNonce, buf: &[u8]) -> io::Result<Header> {
    if buf.len() < MSG_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not enough bytes to read a header",
        ));
    }
    let secret_header = &buf[..MSG_HEADER_LEN];
    match secretbox::open(secret_header, &key_nonce.nonce, &key_nonce.key) {
        Ok(h) => {
            key_nonce.increment_be_inplace();
            Ok(Header::from_bytes(array_ref![&h, 0, 18]))
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
    use std::rc::Rc;

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

        let stream = CircularBuffer::new(64);
        let mut writer = BoxStreamWrite::new(stream,send_key_nonce,2048);
        writer.write_all(b"hola").await?;
        writer.flush().await?;
        
        let BoxStreamWrite { stream , .. } = writer;
        let mut reader = BoxStreamRead::new(stream,recv_key_nonce,2048);
        let mut buffer = [0u8;4];
        reader.read_exact(&mut buffer[..]).await?;

        assert_eq!(b"hola",&buffer);

        Ok(())
    }
}
