use core::fmt;
use std::{convert, io};

#[derive(Debug)]
pub enum Error {
    DecryptHeaderSecretbox,
    DecryptBodySecretbox,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::DecryptHeaderSecretbox => {
                write!(f, "secretbox::open failed in header decryption")
            }
            Error::DecryptBodySecretbox => write!(f, "secretbox::open failed in body decryption"),
        }
    }
}

impl convert::From<Error> for io::Error {
    fn from(error: Error) -> Self {
        match error {
            Error::DecryptHeaderSecretbox => Self::new(io::ErrorKind::InvalidInput, error),
            Error::DecryptBodySecretbox => Self::new(io::ErrorKind::InvalidInput, error),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
impl std::error::Error for Error {}
