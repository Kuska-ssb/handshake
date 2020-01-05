use std::convert;
use sodiumoxide::crypto::{auth, sign::ed25519};
use async_std::{
    prelude::*,
    io,
    io::Read,
    io::Write
};

use crate::handshake::{self, Handshake, HandshakeComplete};

#[derive(Debug)]
pub enum Error {
    Handshake(handshake::Error),
    Io(io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl convert::From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl convert::From<handshake::Error> for Error {
    fn from(error: handshake::Error) -> Self {
        Self::Handshake(error)
    }
}

pub async fn handshake_client<T: Read + Write + Unpin>(
    mut stream: T,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
    server_pk: ed25519::PublicKey,
) -> Result<HandshakeComplete> {
    let mut buf = [0; 128];
    let handshake = Handshake::new_client(net_id, pk, sk);

    let mut send_buf = &mut buf[..handshake.send_bytes()];
    let handshake = handshake.send_client_hello(&mut send_buf);
    stream.write_all(&send_buf).await?;

    let mut recv_buf = &mut buf[..handshake.recv_bytes()];
    stream.read_exact(&mut recv_buf).await?;
    let handshake = handshake.recv_server_hello(&recv_buf)?;

    let mut send_buf = &mut buf[..handshake.send_bytes()];
    let handshake = handshake.send_client_auth(&mut send_buf, server_pk)?;
    stream.write_all(&send_buf).await?;

    let mut recv_buf = &mut buf[..handshake.recv_bytes()];
    stream.read_exact(&mut recv_buf).await?;
    let handshake = handshake.recv_server_accept(&mut recv_buf)?;

    Ok(handshake.complete())
}

pub async fn handshake_server<T: Read + Write + Unpin>(
    mut stream: T,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
) -> Result<HandshakeComplete> {
    let mut buf = [0; 128];
    let handshake = Handshake::new_server(net_id, pk, sk);

    let mut recv_buf = &mut buf[..handshake.recv_bytes()];
    stream.read_exact(&mut recv_buf).await?;
    let handshake = handshake.recv_client_hello(&recv_buf)?;

    let mut send_buf = &mut buf[..handshake.send_bytes()];
    let handshake = handshake.send_server_hello(&mut send_buf);
    stream.write_all(&send_buf).await?;

    let mut recv_buf = &mut buf[..handshake.recv_bytes()];
    stream.read_exact(&mut recv_buf).await?;
    let handshake = handshake.recv_client_auth(&mut recv_buf)?;

    let mut send_buf = &mut buf[..handshake.send_bytes()];
    let handshake = handshake.send_server_accept(&mut send_buf);
    stream.write_all(&send_buf).await?;

    Ok(handshake.complete())
}
