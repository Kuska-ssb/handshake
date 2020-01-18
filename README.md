[![Build Status](https://github.com/kuska-ssb/kuska-handshake/workflows/Rust/badge.svg)](https://github.com/kuska-ssb/kuska-handshake/actions?query=workflow%3ARust) 
[![codecov](https://codecov.io/gh/Kuska-ssb/kuska-handshake/branch/master/graph/badge.svg)](https://codecov.io/gh/Kuska-ssb/kuska-handshake)

# kuska handshake

kuska means _together_ in [Runasimi](https://en.wikipedia.org/wiki/Quechuan_languages)

kuska is an implementation of decentralized social network [Secure Scuttlebut](https://scuttlebutt.nz/) written in rust, it does not aim to provide a user interface and the functionality implemented in some clients like [Patchwork](https://github.com/ssbc/patchwork), [Patchbay](https://github.com/ssbc/patchbay), but the full set of libraries to be able to develop applications for the secure scuttlebut network.

kuska-handshake is the implementation of the handhake and box stream used in SSB, detailed information about the protocol can be found in https://ssbc.github.io/scuttlebutt-protocol-guide/.

the current implementation contains:

- an agnostic implementation of the protcol using [sodiumoxide](https://github.com/sodiumoxide/sodiumoxide)
- a synchronous version (needs `sync` feature)
- an asynchronous `async_std` version (needs `async_std` feature, with wrappers for `tokio` with `tokio_compat` feature)

## sync client/server

#### server

Create the server key pair
```
let (pk, sk) = ed25519::gen_keypair();
let pk_b64 = base64::encode_config(&pk, base64::STANDARD);
```

Define the network to connect
```
let net_id_hex = "d4a1cb88a66f02f8db635ce26441cc5dac1b08420ceaac230839b755845a9ffb";
let net_id = auth::Key::from_slice(&hex::decode(net_id_hex).unwrap()).unwrap();
```

Listen, accept the socket, and perform the handshake
```
let listener = TcpListener::bind(...).unwrap();
let (socket, addr) = listener.accept().unwrap();
let handshake = handshake_server(&socket, net_id, pk, sk)?;
```

Once the handshake is performed, create both box streams, one to send and another to recieve data, 
those box streams implements `std::io::Read` and `std::io::Write` to perform usual i/o operations on them.
```
let (key_nonce_send, key_nonce_recv) = KeyNonce::from_handshake(handshake);
let (mut box_stream_read, mut box_stream_write) =
        BoxStream::new(&socket, &socket, key_nonce_send, key_nonce_recv).split_read_write();

box_stream_read.read_exact(...)
box_stream_write.write_all(...)
```

#### client

Create the client key pair
```
let (pk, sk) = ed25519::gen_keypair();
let pk_b64 = base64::encode_config(&pk, base64::STANDARD);
```

Connect to the server, perform the handshake (you need the server public key), and create the box streams to communicate
```
let socket = TcpStream::connect(...).unwrap();
let handshake = handshake_client(&socket, net_id, pk, sk, server_pk)?;

let (key_nonce_send, key_nonce_recv) = KeyNonce::from_handshake(handshake);
let (mut box_stream_read, mut box_stream_write) =
  BoxStream::new(&socket, &socket, key_nonce_send, key_nonce_recv).split_read_write();

box_stream_read.read_exact(...)
box_stream_write.write_all(...)
```

## async_std client

The `async_std` client is analogous to the `sync` version, just all functions are async and uses `async_std::io::Read` and `async_std::io::Write` for box streams

```
use async_std::io::{Read,Write};
use async_std::net::TcpStream;
use kuska_handshake::async_std::{handshake_client,BoxStream};

#[async_std::main]
async fn main() -> Result<T, Box<dyn Error>> {
  ...
  let mut socket = TcpStream::connect("127.0.0.1:8008").await?;
  let (_,handshake) = handshake_client(&mut socket, ssb_net_id(), pk, sk, server_pk).await?;

  let (box_stream_read, box_stream_write) =
      BoxStream::from_handhake(&socket, &socket, handshake, 0x8000)
      .split_read_write();
```

## tokio client

To use the tokio you need the wrappers used in `kuska_handshake::async_std::tokio_compat`:

```
use tokio::net::TcpStream;
use kuska_handshake::async_std::{BoxStream,handshake_client,TokioCompatExt,TokioCompatExtRead,TokioCompatExtWrite};

let tokio_socket : TcpStream = TcpStream::connect("127.0.0.1:8008").await?;
let asyncstd_socket = TokioCompatExt::wrap(tokio_socket);

let (asyncstd_socket,handshake) = handshake_client(asyncstd_socket, ssb_net_id(), pk, sk.clone(), pk).await?;
let mut tokio_socket = asyncstd_socket.into_inner();
let (read,write) = tokio_socket.split();

let read = TokioCompatExtRead::wrap(read);
let write = TokioCompatExtWrite::wrap(write);

let (box_stream_read, box_stream_write) =
    BoxStream::from_handhake(read, write, handshake, 0x8000)
    .split_read_write();
```
