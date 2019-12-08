use async_std::io;

pub fn to_ioerr<T: ToString>(err: T) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err.to_string())
}

