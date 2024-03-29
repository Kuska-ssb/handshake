use tokio::net::{
    tcp::{ReadHalf, WriteHalf},
    TcpStream,
};

use tokio::io::ReadBuf;

use futures::{
    io::{self, AsyncRead as Read, AsyncWrite as Write},
    task::{Context, Poll},
};
use std::pin::Pin;

pub struct TokioCompat<T>(T);

impl<T> TokioCompat<T> {
    pub fn into_inner(self) -> T {
        self.0
    }
}

pub trait TokioCompatExt: tokio::io::AsyncRead + tokio::io::AsyncWrite + Sized {
    #[inline]
    fn wrap(self) -> TokioCompat<Self> {
        TokioCompat(self)
    }
}

pub trait TokioCompatExtRead: tokio::io::AsyncRead + Sized {
    #[inline]
    fn wrap(self) -> TokioCompat<Self> {
        TokioCompat(self)
    }
}

pub trait TokioCompatExtWrite: tokio::io::AsyncWrite + Sized {
    #[inline]
    fn wrap(self) -> TokioCompat<Self> {
        TokioCompat(self)
    }
}

impl<T: tokio::io::AsyncRead + Unpin> Read for TokioCompat<T> {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<Result<usize, io::Error>> {
        let mut read_buf = ReadBuf::new(buf);
        Pin::new(&mut self.0)
            .poll_read(cx, &mut read_buf)
            .map(|res| res.map(|()| read_buf.filled().len()))
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> Write for TokioCompat<T> {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    #[inline]
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl TokioCompatExt for TcpStream {}
impl TokioCompatExtRead for ReadHalf<'_> {}
impl TokioCompatExtWrite for WriteHalf<'_> {}
impl TokioCompatExtRead for tokio::io::ReadHalf<TcpStream> {}
impl TokioCompatExtWrite for tokio::io::WriteHalf<TcpStream> {}
