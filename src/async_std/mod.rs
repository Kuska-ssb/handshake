mod boxstream;
mod error;
mod handshake;
#[cfg(feature = "tokio_compat")]
mod tokio_compat;

#[cfg(test)]
mod circularbuffer;

pub use boxstream::{BoxStream, BoxStreamRead, BoxStreamWrite};
pub use error::{Error, Result};
pub use handshake::{handshake_client, handshake_server};

#[cfg(feature = "tokio_compat")]
pub use tokio_compat::{TokioCompat, TokioCompatExt, TokioCompatExtRead, TokioCompatExtWrite};
