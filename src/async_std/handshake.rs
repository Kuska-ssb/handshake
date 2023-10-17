use super::error::{Error, Result};

use futures::{
    io::{self, AsyncRead as Read, AsyncWrite as Write},
    AsyncReadExt, AsyncWriteExt,
};

use sodiumoxide::crypto::{auth, sign::ed25519};
use std::convert;

use crate::handshake::{self, Handshake, HandshakeComplete};

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
    stream: &mut T,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
    server_pk: ed25519::PublicKey,
) -> Result<HandshakeComplete> {
    let mut buf = [0; 128];
    let handshake = Handshake::new_client(net_id, pk, sk);

    let send_buf = &mut buf[..handshake.send_bytes()];
    let handshake = handshake.send_client_hello(send_buf);
    stream.write_all(send_buf).await?;

    let recv_buf = &mut buf[..handshake.recv_bytes()];
    stream.read_exact(recv_buf).await?;
    let handshake = handshake.recv_server_hello(recv_buf)?;

    let send_buf = &mut buf[..handshake.send_bytes()];
    let handshake = handshake.send_client_auth(send_buf, server_pk)?;
    stream.write_all(send_buf).await?;

    let recv_buf = &mut buf[..handshake.recv_bytes()];
    stream.read_exact(recv_buf).await?;
    let handshake = handshake.recv_server_accept(recv_buf)?;

    Ok(handshake.complete())
}

pub async fn handshake_server<T: Read + Write + Unpin>(
    stream: &mut T,
    net_id: auth::Key,
    pk: ed25519::PublicKey,
    sk: ed25519::SecretKey,
) -> Result<HandshakeComplete> {
    let mut buf = [0; 128];
    let handshake = Handshake::new_server(net_id, pk, sk);

    let recv_buf = &mut buf[..handshake.recv_bytes()];
    stream.read_exact(recv_buf).await?;
    let handshake = handshake.recv_client_hello(recv_buf)?;

    let send_buf = &mut buf[..handshake.send_bytes()];
    let handshake = handshake.send_server_hello(send_buf);
    stream.write_all(send_buf).await?;

    let recv_buf = &mut buf[..handshake.recv_bytes()];
    stream.read_exact(recv_buf).await?;
    let handshake = handshake.recv_client_auth(recv_buf)?;

    let send_buf = &mut buf[..handshake.send_bytes()];
    let handshake = handshake.send_server_accept(send_buf);
    stream.write_all(send_buf).await?;

    Ok(handshake.complete())
}

#[cfg(test)]
mod tests {
    use super::*;

    use async_std::{
        io::{Read, Write},
        prelude::*,
    };

    use test_utils::net_async::{net, net_fragment};

    const NET_ID_HEX: &str = "d4a1cb88a66f02f8db635ce26441cc5dac1b08420ceaac230839b755845a9ffb";
    const CLIENT_SEED_HEX: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";
    const SERVER_SEED_HEX: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";

    // Perform a handshake between two connected streams
    async fn handshake_aux<T: Write + Read + Unpin>(mut stream_client: T, mut stream_server: T) {
        let net_id = auth::Key::from_slice(&hex::decode(NET_ID_HEX).unwrap()).unwrap();
        let (client_pk, client_sk) = ed25519::keypair_from_seed(
            &ed25519::Seed::from_slice(&hex::decode(CLIENT_SEED_HEX).unwrap()).unwrap(),
        );
        let (server_pk, server_sk) = ed25519::keypair_from_seed(
            &ed25519::Seed::from_slice(&hex::decode(SERVER_SEED_HEX).unwrap()).unwrap(),
        );

        let net_id_cpy = net_id.clone();

        let future_client =
            handshake_client(&mut stream_client, net_id, client_pk, client_sk, server_pk);
        let future_server = handshake_server(&mut stream_server, net_id_cpy, server_pk, server_sk);

        let (client_handshake, server_handshake) = future_client.join(future_server).await;
        let client_handshake = client_handshake.unwrap();
        let server_handshake = server_handshake.unwrap();

        assert_eq!(client_handshake.net_id, server_handshake.net_id);
        assert_eq!(
            client_handshake.shared_secret,
            server_handshake.shared_secret
        );
        assert_eq!(client_handshake.pk, server_handshake.peer_pk);
        assert_eq!(
            client_handshake.ephemeral_pk,
            server_handshake.peer_ephemeral_pk
        );
        assert_eq!(client_handshake.peer_pk, server_handshake.pk);
        assert_eq!(
            client_handshake.peer_ephemeral_pk,
            server_handshake.ephemeral_pk
        );
    }

    #[async_std::test]
    async fn test_handshake_async() {
        net(|a, _, b, _| handshake_aux(a, b)).await;
    }

    #[async_std::test]
    async fn test_handshake_async_fragment() {
        net_fragment(5, |a, _, b, _| handshake_aux(a, b)).await;
    }
}
