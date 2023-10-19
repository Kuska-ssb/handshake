extern crate log;
pub extern crate sodiumoxide;

#[macro_use]
pub mod utils;

#[cfg(feature = "sync")]
pub mod sync;

#[cfg(feature = "async_std")]
pub mod async_std;

mod boxstream;
mod handshake;

pub use boxstream::{
    BoxStreamRecv, BoxStreamSend, Error as BoxstreamError, Header, KeyNonce,
    Result as BoxstreamResult,
};
pub use handshake::{
    Error as HandshakeError, Handshake, HandshakeComplete, Result as HandshakeResult,
    SendServerAccept, SharedSecret,
};
