extern crate log;
extern crate sodiumoxide;

use crate::handshake::{HandshakeComplete, SharedSecret};
use crate::utils::Buffer;
use log::debug;

use futures::io::{self}; //, AsyncRead, AsyncWrite};
                         // use futures::task::{Context, Poll};
use sodiumoxide::crypto::{auth, hash::sha256, scalarmult::curve25519, secretbox};
use std::{cmp, io::Read, io::Write}; //, pin::Pin};

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
    key_nonce.nonce.increment_le_inplace();
    let body_nonce = key_nonce.nonce;
    key_nonce.nonce.increment_le_inplace();
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
    let header = Header {
        body_len: body.len(),
        body_mac: body_tag,
    };
    header_body_buf.copy_from_slice(&header.to_bytes());
    let header_tag = secretbox::seal_detached(&mut header_body_buf, &header_nonce, &key_nonce.key);
    header_tag_buf.copy_from_slice(header_tag.as_ref());
    // debug!("header_tag_buf {:?}", header_tag_buf);
    // debug!("header_body_buf {:?}", header_body_buf);
    return body.len();
}

fn decrypt_box_stream_header(key_nonce: &mut KeyNonce, buf: &mut [u8]) -> io::Result<Header> {
    if buf.len() < MSG_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "not enough bytes to read a header",
        ));
    }
    debug!("decrypt header buf len: {}", buf.len());
    debug!(
        "decrypt header_nonce: {}",
        hex::encode(key_nonce.nonce.as_ref())
    );
    let (header_tag_buf, mut header_body_buf) =
        buf[..MSG_HEADER_LEN].split_at_mut(secretbox::MACBYTES);
    // debug!("header_tag_buf {:?}", header_tag_buf);
    // debug!("header_body_buf {:?}", header_body_buf);
    match secretbox::open_detached(
        &mut header_body_buf,
        &secretbox::Tag::from_slice(&header_tag_buf).unwrap(),
        &key_nonce.nonce,
        &key_nonce.key,
    ) {
        Ok(()) => {
            key_nonce.nonce.increment_le_inplace();
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
    debug!(
        "decrypt body_nonce: {}",
        hex::encode(key_nonce.nonce.as_ref())
    );
    let mut body_buf = &mut buf[..header.body_len];
    match secretbox::open_detached(
        &mut body_buf,
        &header.body_mac,
        &key_nonce.nonce,
        &key_nonce.key,
    ) {
        Ok(()) => {
            key_nonce.nonce.increment_le_inplace();
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

pub struct BoxStreamWrite<'a, W> {
    stream: W,
    key_nonce: KeyNonce,
    // buf: Vec<u8>,
    // buf_cap: usize,
    enc: &'a mut [u8],
    // enc_pos: usize,
    // enc_cap: usize,
}

impl<'a, W: Write> Write for BoxStreamWrite<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // let enc_buf = Buffer::new(&mut self.enc);
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
        debug!(
            "buf.len: {}, self.enc.len: {}, self.enc.capacity: {}",
            buf.len(),
            enc_n,
            self.enc.len()
        );
        // Write all the encrypted messages to the stream
        self.stream.write_all(&self.enc[..enc_n])?;
        // Reset the self.enc buffer
        // self.enc.clear();
        debug!("Written {} bytes", buf_n);
        Ok(buf_n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

enum RecvStatus {
    ExpectHeader,
    ExpectBody(Header),
}

pub struct BoxStreamRead<'a, R> {
    stream: R,
    key_nonce: KeyNonce,
    // buf: Box<[u8]>,
    // buf_cap: usize,
    enc: &'a mut [u8],
    enc_cap: usize,
    // dec: Box<[u8]>,
    // dec_pos: usize,
    // dec_cap: usize,
    status: RecvStatus,
    need_more_bytes: bool,
}

impl<'a, R: Read> Read for BoxStreamRead<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.need_more_bytes {
            self.enc_cap += self.stream.read(&mut self.enc[self.enc_cap..])?;
        }
        debug!("read {} bytes", self.enc_cap);
        let mut enc_pos = 0;
        let mut buf_pos = 0;
        loop {
            let result = match self.status {
                // The first part of a BoxStream message is a fixed length header
                RecvStatus::ExpectHeader => {
                    match decrypt_box_stream_header(
                        &mut self.key_nonce,
                        &mut self.enc[enc_pos..self.enc_cap],
                    ) {
                        Ok(header) => {
                            enc_pos += MSG_HEADER_LEN;
                            debug!("Header enc_pos: {}", enc_pos);
                            self.status = RecvStatus::ExpectBody(header);
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
                RecvStatus::ExpectBody(ref header) => {
                    if buf.len() - buf_pos < header.body_len {
                        // Not enough space in buf to decrypt the next body
                        break;
                    }
                    match decrypt_box_stream_body(
                        header,
                        &mut self.key_nonce,
                        &mut self.enc[enc_pos..self.enc_cap],
                    ) {
                        Ok(n) => {
                            buf[buf_pos..buf_pos + n]
                                .copy_from_slice(&self.enc[enc_pos..self.enc_cap]);
                            enc_pos += n;
                            debug!("Body enc_pos: {}", enc_pos);
                            buf_pos += header.body_len;
                            self.status = RecvStatus::ExpectHeader;
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }
            };
            if let Err(e) = result {
                match e.kind() {
                    io::ErrorKind::InvalidInput => {
                        // If there are encrypted bytes left but not enough to decrypt a
                        // header/body, we need to read more bytes next time.
                        if enc_pos < self.enc_cap {
                            self.need_more_bytes = true;
                        }
                        break;
                    }
                    _ => {
                        return Err(e);
                    }
                }
            }
        }
        self.enc.copy_within(enc_pos..self.enc_cap, 0);
        self.enc_cap = self.enc_cap - enc_pos;
        debug!("Read {} bytes", buf_pos);
        Ok(buf_pos)
    }
}

pub struct BoxStream<'a, 'b, R, W> {
    reader: BoxStreamRead<'a, R>,
    writer: BoxStreamWrite<'b, W>,
}

impl<'a, 'b, R, W> BoxStream<'a, 'b, R, W> {
    pub fn split_read_write(self) -> (BoxStreamRead<'a, R>, BoxStreamWrite<'b, W>) {
        let BoxStream { reader, writer } = self;
        (reader, writer)
    }
}

impl<'a, 'b, R, W> BoxStream<'a, 'b, R, W> {
    pub fn new(
        read_stream: R,
        write_stream: W,
        read_buf: &'a mut [u8],
        write_buf: &'b mut [u8],
        handshake_complete: HandshakeComplete,
    ) -> Self {
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
        let send_key_nonce = KeyNonce {
            key: secretbox::Key(
                sha256::hash(&[shared_secret_1.as_ref(), peer_pk.as_ref()].concat()).0,
            ),
            nonce: secretbox::Nonce::from_slice(&send_hmac_nonce.as_ref()[..secretbox::NONCEBYTES])
                .unwrap(),
        };
        let recv_hmac_nonce = auth::authenticate(ephemeral_pk.as_ref(), &net_id);
        let recv_key_nonce = KeyNonce {
            key: secretbox::Key(sha256::hash(&[shared_secret_1.as_ref(), pk.as_ref()].concat()).0),
            nonce: secretbox::Nonce::from_slice(&recv_hmac_nonce.as_ref()[..secretbox::NONCEBYTES])
                .unwrap(),
        };
        // let capacity = cmp::max(MSG_HEADER_LEN + MSG_BODY_MAX_LEN, recv_buf_len);
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
        let reader = BoxStreamRead {
            stream: read_stream,
            key_nonce: recv_key_nonce,
            // buf: vec![0; capacity].into_boxed_slice(),
            // buf_cap: 0,
            // enc: vec![0; capacity].into_boxed_slice(),
            enc: read_buf,
            enc_cap: 0,
            // dec: vec![0; capacity].into_boxed_slice(),
            // dec_pos: 0,
            // dec_cap: 0,
            status: RecvStatus::ExpectHeader,
            need_more_bytes: true,
        };
        let writer = BoxStreamWrite {
            stream: write_stream,
            key_nonce: send_key_nonce,
            // buf: Vec::with_capacity(MSG_BODY_MAX_LEN),
            // buf_cap: 0,
            // enc: &[0; capacity],
            enc: write_buf,
            // enc_pos: 0,
            // enc_cap: 0,
        };
        Self { reader, writer }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boxstream() {}
}

// Not working yet
// impl<W: AsyncWrite + Unpin> AsyncWrite for BoxStream<W> {
//     fn poll_write(
//         mut self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         buf: &[u8],
//     ) -> Poll<io::Result<usize>> {
//         // If we can't buffer any more, flush
//         if self.send.enc.len() + buf.len() > self.send.enc.capacity() {
//             match Pin::new(&mut self).poll_flush(cx) {
//                 Poll::Ready(Err(e)) => {
//                     return Poll::Ready(Err(e));
//                 }
//                 Poll::Pending => {
//                     return Poll::Pending;
//                 }
//                 _ => {}
//             }
//         }
//         let BoxStream { stream, send, .. } = self.get_mut();
//         // If we don't have enough capacity to buffer, write direclty
//         // if buf.len() > self.enc.capacity() {
//         //     // Write directly?
//         // } else {
//         //     buffer
//         // }
//         let mut buf_pos = 0;
//         loop {
//             if buf[buf_pos..].len() < MSG_BODY_MAX_LEN {
//                 break;
//             }
//             buf_pos += encrypt_box_stream_msg(&mut send.key_nonce, &buf[buf_pos..], &mut send.enc);
//         }
//         // If send.enc is full, write it to the stream
//         if send.enc_pos < send.enc_cap {
//             let poll = Pin::new(stream).poll_write(cx, &send.enc[send.enc_pos..send.enc_cap]);
//             match poll {
//                 Poll::Ready(Ok(n)) => {
//                     send.enc_pos += n;
//                 }
//                 Poll::Ready(Err(e)) => {
//                     return Poll::Ready(Err(e));
//                 }
//                 Poll::Pending => {
//                     return Poll::Pending;
//                 }
//             }
//         }
//         Poll::Pending
//     }
//
//     fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
//         let BoxStream { stream, .. } = self.get_mut();
//         Pin::new(stream).poll_flush(cx)
//     }
//
//     fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
//         let BoxStream { stream, .. } = self.get_mut();
//         Pin::new(stream).poll_close(cx)
//     }
// }

// Decrypt BoxStream messages from recv.buf into recv.dec.  Return the position of the first
// non-decrypted byte in recv.buf.
// fn decrypt_box_stream(recv: &mut BoxStreamRead) -> io::Result<usize> {
//     let mut buf_pos = 0;
//     // Decrypt messages from the recv.buf in a loop
//     loop {
//         match recv.status {
//             // The first part of a BoxStream message is a fixed length header
//             RecvStatus::ExpectHeader => {
//                 // Try to decrypt the header from the received buffer
//                 if recv.buf_cap - buf_pos < MSG_HEADER_LEN {
//                     return Ok(buf_pos);
//                 }
//                 let secret_header = &recv.buf[buf_pos..buf_pos + MSG_HEADER_LEN];
//                 buf_pos += MSG_HEADER_LEN;
//                 match secretbox::open(secret_header, &recv.key_nonce.nonce, &recv.key_nonce.key) {
//                     Ok(h) => {
//                         recv.key_nonce.nonce.increment_le_inplace();
//                         let header = Header::from_bytes(array_ref![&h, 0, 18]);
//                         // Set the status to ExpectBody(header) in order to read the body
//                         // referenced in the header in the next iteration.
//                         recv.status = RecvStatus::ExpectBody(header);
//                     }
//                     Err(()) => {
//                         return Err(io::Error::new(
//                             io::ErrorKind::Other,
//                             "secretbox::open for header failed",
//                         ));
//                     }
//                 };
//             }
//             // The second part of a BoxStream message is a variable length body.
//             // Use the header from the previous ExpectHeader state decryption
//             RecvStatus::ExpectBody(ref header) => {
//                 if recv.buf_cap - buf_pos < header.body_len {
//                     return Ok(buf_pos);
//                 }
//                 let secret_body = &[
//                     header.body_mac.as_ref(),
//                     &recv.buf[buf_pos..buf_pos + header.body_len],
//                 ]
//                 .concat();
//                 buf_pos += header.body_len;
//                 let body = match secretbox::open(
//                     secret_body,
//                     &recv.key_nonce.nonce,
//                     &recv.key_nonce.key,
//                 ) {
//                     Ok(body) => {
//                         recv.key_nonce.nonce.increment_le_inplace();
//                         // Set the status to ExpectHeader in order to read a header in the next
//                         // iteration.
//                         recv.status = RecvStatus::ExpectHeader;
//                         body
//                     }
//                     Err(()) => {
//                         return Err(io::Error::new(
//                             io::ErrorKind::Other,
//                             "secretbox::open for body failed",
//                         ));
//                     }
//                 };
//                 // Write the decrypted body at recv.dec
//                 recv.dec[recv.dec_cap..recv.dec_cap + body.len()].copy_from_slice(&body);
//                 buf_pos += body.len();
//                 recv.dec_cap += body.len();
//             }
//         }
//     }
// }

// impl<R: AsyncRead + Unpin> AsyncRead for BoxStream<R> {
//     fn poll_read(
//         self: Pin<&mut Self>,
//         cx: &mut Context<'_>,
//         buf: &mut [u8],
//     ) -> Poll<io::Result<usize>> {
//         let BoxStream { stream, recv, .. } = self.get_mut();
//         // Decrypted buffer is empty, we must fill it
//         if recv.dec_pos == recv.dec_pos {
//             recv.dec_pos = 0;
//             recv.dec_cap = 0;
//             let poll = Pin::new(stream).poll_read(cx, &mut recv.buf[recv.buf_cap..]);
//             match poll {
//                 Poll::Ready(Ok(n)) => {
//                     recv.buf_cap += n;
//                 }
//                 Poll::Ready(Err(e)) => {
//                     return Poll::Ready(Err(e));
//                 }
//                 Poll::Pending => {
//                     return Poll::Pending;
//                 }
//             }
//             match decrypt_box_stream(recv) {
//                 Err(e) => {
//                     return Poll::Ready(Err(e));
//                 }
//                 Ok(buf_pos) => {
//                     // Reset recv.buf by forgetting the decrypted bytes and moving the decrypted
//                     // bytes to the beginning.
//                     recv.buf.copy_within(buf_pos..recv.buf_cap, 0);
//                     recv.buf_cap = recv.buf_cap - buf_pos;
//                 }
//             }
//         }
//         // We have some decrypted data to give back
//         if recv.dec_pos < recv.dec_cap {
//             let len = cmp::min(buf.len(), recv.dec_cap - recv.dec_pos);
//             buf[..len].copy_from_slice(&recv.dec[recv.dec_pos..recv.dec_pos + len]);
//             recv.dec_pos += len;
//             return Poll::Ready(Ok(len));
//         }
//         return Poll::Pending;
//     }
// }
