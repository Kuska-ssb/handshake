use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("performing handshake: {0}")]
    Handshake(crate::handshake::Error),
    #[error("i/o: {0}")]
    Io(futures::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
