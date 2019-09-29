#[macro_use]
extern crate arrayref;
extern crate sodiumoxide;

use std::{
    pin::Pin,
    cmp,
    io::Read,
    io::Write,
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

mod handshake {
    use std::{
        io,
        io::Result,
        io::Read,
        io::Write,
    };
    use sodiumoxide::crypto::{
        sign::ed25519,
        auth,
        hash::sha256,
        secretbox,
        scalarmult::curve25519,
    };

    pub struct HandshakeBase<T> {
        stream: T,
        net_id: auth::Key,
        pk: ed25519::PublicKey,
        sk: ed25519::SecretKey,
        ephemeral_pk: curve25519::GroupElement,
        ephemeral_sk: curve25519::Scalar,
    }

    pub struct Handshake<T, S: State> {
        base: HandshakeBase<T>,
        state: S,
    }

    // Client States
    struct SendClientHello;
    struct RecvServerHello;
    struct SendClientAuth;
    struct RecvServerAccept;

    // Server States
    struct RecvClientHello;
    struct SendServerHello;
    struct RecvClientAuth;
    struct SendServerAccept;

    // Shared States
    struct Complete;

    pub trait State {}
    impl State for SendClientHello {}
    impl State for RecvServerHello {}
    impl State for SendClientAuth {}
    impl State for RecvServerAccept {}

    impl State for RecvClientHello {}
    impl State for SendServerHello {}
    impl State for RecvClientAuth {}
    impl State for SendServerAccept {}

    impl State for Complete {}

    // Client
    impl<T, S: State> Handshake<T, S> {
        fn new_client(
            stream: T,
            net_id: auth::Key,
            pk: ed25519::PublicKey,
            sk: ed25519::SecretKey) -> Handshake<T, SendClientHello> {
            let (ephemeral_ed_pk, ephemeral_ed_sk) = ed25519::gen_keypair();
            let ephemeral_pk = ephemeral_ed_pk.to_curve25519();
            let ephemeral_sk = ephemeral_ed_sk.to_curve25519();
            let state = SendClientHello;
            let base = HandshakeBase{ stream, net_id, pk, sk, ephemeral_pk, ephemeral_sk };
            Handshake{ base, state }
        }
    }

    impl<T: Write> Handshake<T, SendClientHello> {
        fn send_client_hello(mut self) -> Result<Handshake<T, RecvServerHello>> {
            let send = [
                auth::authenticate(self.base.ephemeral_pk.as_ref(), &self.base.net_id).as_ref(),
                self.base.ephemeral_pk.as_ref(),
            ].concat();
            self.base.stream.write_all(&send)?;
            self.base.stream.flush()?;
            let state = RecvServerHello;
            Ok(Handshake{ base: self.base, state: state })
        }
    }

    impl<T: Read> Handshake<T, RecvServerHello> {
        fn recv_server_hello(
            mut self,
            server_pk: ed25519::PublicKey) -> Result<Handshake<T, SendClientAuth>> {
            let mut recv = [0; 64];
            self.base.stream.read_exact(&mut recv)?;
            let server_hmac = auth::Tag::from_slice(&recv[..32]).unwrap();
            let server_ephemeral_pk = curve25519::GroupElement::from_slice(&recv[32..]).unwrap();
            if !auth::verify(&server_hmac, server_ephemeral_pk.as_ref(), &self.base.net_id) {
                return Err(io::Error::new(io::ErrorKind::Other,
                        "auth::verify failed in recv_server_hello"));
            }
            let shared_secret_ab = curve25519::scalarmult(
                &self.base.ephemeral_sk,
                &server_ephemeral_pk).unwrap();
            let shared_secret_aB = curve25519::scalarmult(
                &self.base.ephemeral_sk,
                &server_pk.to_curve25519()).unwrap();
            let state = SendClientAuth;
            Ok(Handshake{ base: self.base, state: state })
        }
    }

    // impl<T: Write> Handshake<T, SendClientAuth> {
    //     fn send_client_auth(self) -> Result<Handshake<T, RecvServerAccept>> {
    //         Ok(Handshake{
    //             stream: self.stream,
    //             state: RecvServerAccept,
    //         })
    //     }
    // }

    // impl<T: Read> Handshake<T, RecvServerAccept> {
    //     fn recv_server_accept(self) -> Result<Handshake<T, Complete>> {
    //         Ok(Handshake{
    //             stream: self.stream,
    //             state: Complete,
    //         })
    //     }
    // }

    // // Server
    // // impl<T, S: State> Handshake<T, S> {
    // //     fn new_server(stream: T) -> Handshake<T, RecvClientHello> {
    // //         Handshake{
    // //             stream: stream,
    // //             state: RecvClientHello,
    // //         }
    // //     }
    // // }

    // impl<T: Read> Handshake<T, RecvClientHello> {
    //     fn send_client_hello(self) -> Result<Handshake<T, SendServerHello>> {
    //         Ok(Handshake{
    //             stream: self.stream,
    //             state: SendServerHello,
    //         })
    //     }
    // }

    // impl<T: Write> Handshake<T, SendServerHello> {
    //     fn recv_server_hello(self) -> Result<Handshake<T, RecvClientAuth>> {
    //         Ok(Handshake{
    //             stream: self.stream,
    //             state: RecvClientAuth,
    //         })
    //     }
    // }

    // impl<T: Read> Handshake<T, RecvClientAuth> {
    //     fn send_client_auth(self) -> Result<Handshake<T, SendServerAccept>> {
    //         Ok(Handshake{
    //             stream: self.stream,
    //             state: SendServerAccept,
    //         })
    //     }
    // }

    // impl<T: Write> Handshake<T, SendServerAccept> {
    //     fn recv_server_accept(self) -> Result<Handshake<T, Complete>> {
    //         Ok(Handshake{
    //             stream: self.stream,
    //             state: Complete,
    //         })
    //     }
    // }
}


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
    recv: BoxStreamRecv,
    send: BoxStreamSend,
}

enum RecvStatus {
    ExpectHeader,
    ExpectBody(Header),
}

struct BoxStreamRecv {
    key_nonce: KeyNonce,
    buf: Box<[u8]>,
    buf_cap: usize,
    enc: Box<[u8]>,
    enc_cap: usize,
    dec: Box<[u8]>,
    dec_pos: usize,
    dec_cap: usize,
    status: RecvStatus,
    need_more_bytes: bool,
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
            enc: vec![0; capacity].into_boxed_slice(),
            enc_cap: 0,
            dec: vec![0; capacity].into_boxed_slice(),
            dec_pos: 0,
            dec_cap: 0,
            status: RecvStatus::ExpectHeader,
            need_more_bytes: true,
        };
        let send = BoxStreamSend {
            key_nonce: send_key_nonce,
            buf: Vec::with_capacity(MSG_BODY_MAX_LEN),
            buf_cap: 0,
            enc: Vec::with_capacity(capacity),
            enc_pos: 0,
            enc_cap: 0,
        };
        Self{ stream, send, recv }
    }
}

// Decrypt BoxStream messages from recv.buf into recv.dec.  Return the position of the first
// non-decrypted byte in recv.buf.
fn decrypt_box_stream(recv: &mut BoxStreamRecv) -> io::Result<usize> {
    let mut buf_pos = 0;
    // Decrypt messages from the recv.buf in a loop
    loop {
        match recv.status {
            // The first part of a BoxStream message is a fixed length header
            RecvStatus::ExpectHeader => {
                // Try to decrypt the header from the received buffer
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
                        let header = Header::from_bytes(array_ref![&h, 0, 18]);
                        // Set the status to ExpectBody(header) in order to read the body
                        // referenced in the header in the next iteration.
                        recv.status = RecvStatus::ExpectBody(header);
                    },
                    Err(()) => {
                        return Err(io::Error::new(io::ErrorKind::Other,
                                "secretbox::open for header failed"));
                    }
                };
            }
            // The second part of a BoxStream message is a variable length body.
            // Use the header from the previous ExpectHeader state decryption
            RecvStatus::ExpectBody(ref header) => {
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
                    Ok(body) => {
                        recv.key_nonce.nonce.increment_le_inplace();
                        // Set the status to ExpectHeader in order to read a header in the next
                        // iteration.
                        recv.status = RecvStatus::ExpectHeader;
                        body
                    },
                    Err(()) => {
                        return Err(io::Error::new(io::ErrorKind::Other,
                                "secretbox::open for body failed"));
                    }
                };
                // Write the decrypted body at recv.dec
                recv.dec[recv.dec_cap..recv.dec_cap + body.len()].copy_from_slice(&body);
                buf_pos += body.len();
                recv.dec_cap += body.len();
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BoxStream<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
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
        if recv.dec_pos < recv.dec_cap {
            let len = cmp::min(buf.len(), recv.dec_cap - recv.dec_pos);
            buf[..len].copy_from_slice(&recv.dec[recv.dec_pos..recv.dec_pos+len]);
            recv.dec_pos += len;
            return Poll::Ready(Ok(len));
        }
        return Poll::Pending;
    }
}

struct BoxStreamSend {
    key_nonce: KeyNonce,
    buf: Vec<u8>,
    buf_cap: usize,
    enc: Vec<u8>,
    enc_pos: usize,
    enc_cap: usize,
}

// Encrypt a single message from buf into enc
fn encrypt_box_stream_msg(key_nonce: &mut KeyNonce, buf: &[u8], enc: &mut Vec<u8>) -> usize {
    let body = &buf[..cmp::min(buf.len(), MSG_BODY_MAX_LEN)];

    let header_nonce = key_nonce.nonce;
    key_nonce.nonce.increment_le_inplace();
    let body_nonce = key_nonce.nonce;
    key_nonce.nonce.increment_le_inplace();

    let secret_body = secretbox::seal(
        body,
        &body_nonce,
        &key_nonce.key,
    );
    let header = Header {
        body_len: body.len(),
        body_mac: *array_ref![secret_body, 0, secretbox::MACBYTES],
    };
    let secret_header = secretbox::seal(
        &header.to_bytes(),
        &header_nonce,
        &key_nonce.key,
    );
    enc.write(&secret_header);
    enc.write(&secret_body[secretbox::MACBYTES..]);
    return body.len()
}

fn decrypt_box_stream_header(key_nonce: &mut KeyNonce, buf: &[u8]) -> io::Result<Header> {
    if buf.len() < MSG_HEADER_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "not enough bytes to read a header"));
    }
    let secret_header = &buf[..MSG_HEADER_LEN];
    match secretbox::open(
        secret_header,
        &key_nonce.nonce,
        &key_nonce.key
    ) {
        Ok(h) => {
            key_nonce.nonce.increment_le_inplace();
            Ok(Header::from_bytes(array_ref![&h, 0, 18]))
        },
        Err(()) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                    "secretbox::open for header failed"));
        }
    }
}

fn decrypt_box_stream_body(header: &Header, key_nonce: &mut KeyNonce, buf: &[u8], dec: &mut [u8]) -> io::Result<usize> {
    if buf.len() < header.body_len {
        return Err(io::Error::new(io::ErrorKind::InvalidInput,
                "not enough bytes to read the body"));
    }
    let secret_body = &[
        header.body_mac.as_ref(),
        &buf[..header.body_len]
    ].concat();
    match secretbox::open(
        secret_body,
        &key_nonce.nonce,
        &key_nonce.key
    ) {
        Ok(body) => {
            key_nonce.nonce.increment_le_inplace();
            dec[..header.body_len].copy_from_slice(&body);
            Ok(header.body_len)
        },
        Err(()) => {
            return Err(io::Error::new(io::ErrorKind::InvalidData,
                    "secretbox::open for body failed"));
        }
    }
}

impl<W: Write> Write for BoxStream<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Encrypt into as many messages as we can fit in the self.send.enc buffer
        let mut buf_pos = 0;
        while buf_pos < buf.len() && self.send.enc.len() + MSG_HEADER_LEN + MSG_BODY_MAX_LEN < self.send.enc.capacity() {
            buf_pos += encrypt_box_stream_msg(&mut self.send.key_nonce, &buf[buf_pos..],
                &mut self.send.enc);
        }
        // Write all the encrypted messages to the stream
        let mut n = 0;
        while n < self.send.enc.len() {
            n += self.stream.write(&self.send.enc[n..])?;
        }
        // Reset the self.send.enc buffer
        self.send.enc.clear();
        Ok(buf_pos)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl<R: Read> Read for BoxStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.recv.need_more_bytes {
            self.recv.enc_cap += self.stream.read(&mut self.recv.enc[self.recv.enc_cap..])?;
        }
        let mut enc_pos = 0;
        let mut buf_pos = 0;
        loop {
            let result = match self.recv.status {
                // The first part of a BoxStream message is a fixed length header
                RecvStatus::ExpectHeader => {
                    match decrypt_box_stream_header(&mut self.recv.key_nonce, &self.recv.enc[enc_pos..]) {
                        Ok(header) => {
                            enc_pos += MSG_HEADER_LEN;
                            self.recv.status = RecvStatus::ExpectBody(header);
                            Ok(())
                        }
                        Err(e) => Err(e)
                    }
                }
                RecvStatus::ExpectBody(ref header) => {
                    if buf.len() - buf_pos < header.body_len {
                        // Not enough space in buf to decrypt the next body
                        break;
                    }
                    match decrypt_box_stream_body(header, &mut self.recv.key_nonce, &self.recv.enc[enc_pos..], &mut buf[buf_pos..]) {
                        Ok(n) => {
                            enc_pos += n;
                            buf_pos += header.body_len;
                            self.recv.status = RecvStatus::ExpectHeader;
                            Ok(())
                        }
                        Err(e) => Err(e)
                    }
                }
            };
            if let Err(e) = result {
                match e.kind() {
                    io::ErrorKind::InvalidInput => {
                        // If there are encrypted bytes left but not enough to decrypt a
                        // header/body, we need to read more bytes next time.
                        if enc_pos < self.recv.enc_cap {
                            self.recv.need_more_bytes = true;
                        }
                        break;
                    }
                    _ => {
                        return Err(e);
                    }
                }
            }
        }
        self.recv.enc.copy_within(enc_pos..self.recv.enc_cap, 0);
        self.recv.enc_cap = self.recv.enc_cap - enc_pos;
        Ok(buf_pos)
    }
}

// Not working yet
impl<W: AsyncWrite + Unpin> AsyncWrite for BoxStream<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // If we can't buffer any more, flush
        if self.send.enc.len() + buf.len() > self.send.enc.capacity() {
            match Pin::new(&mut self).poll_flush(cx) {
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
                _ => {}
            }
        }
        let BoxStream { stream, send, .. } = self.get_mut();
        // If we don't have enough capacity to buffer, write direclty
        // if buf.len() > self.enc.capacity() {
        //     // Write directly?
        // } else {
        //     buffer
        // }
        let mut buf_pos = 0;
        loop {
            if buf[buf_pos..].len() < MSG_BODY_MAX_LEN {
                break;
            }
            buf_pos += encrypt_box_stream_msg(&mut send.key_nonce, &buf[buf_pos..], &mut send.enc);
        }
        // If send.enc is full, write it to the stream
        if send.enc_pos < send.enc_cap {
            let poll = Pin::new(stream).poll_write(cx, &send.enc[send.enc_pos..send.enc_cap]);
            match poll {
                Poll::Ready(Ok(n)) => {
                    send.enc_pos += n;
                }
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => {
                    return Poll::Pending;
                }
            }
        }
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let BoxStream { stream, .. } = self.get_mut();
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let BoxStream { stream, .. } = self.get_mut();
        Pin::new(stream).poll_close(cx)
    }
}

fn main() {

}
