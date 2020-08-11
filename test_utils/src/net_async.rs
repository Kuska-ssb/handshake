use async_std::{
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    prelude::*,
};
use futures::future::{self, Either, Future};
use std::time::Duration;

// Run function `op`(a_rd, a_wr, b_rd, b_wr) where (a_rd, a_wr) is the one read/write end of a stream
// and (b_rd, b_wr) is the other read/write end of the same stream.
pub async fn net<O, F, T>(op: O) -> T
where
    O: FnOnce(UnixStream, UnixStream, UnixStream, UnixStream) -> F,
    F: Future<Output = T>,
{
    let (mut stream_a, mut stream_b) = std::os::unix::net::UnixStream::pair().unwrap();
    for stream in &[&mut stream_a, &mut stream_b] {
        stream.set_read_timeout(Some(Duration::new(5, 0))).unwrap();
    }
    let stream_a_read = UnixStream::from(stream_a.try_clone().unwrap());
    let stream_a_write = UnixStream::from(stream_a.try_clone().unwrap());
    let stream_b_read = UnixStream::from(stream_b.try_clone().unwrap());
    let stream_b_write = UnixStream::from(stream_b.try_clone().unwrap());
    let res = op(stream_a_read, stream_a_write, stream_b_read, stream_b_write).await;
    stream_a.shutdown(Shutdown::Both).unwrap();
    stream_b.shutdown(Shutdown::Both).unwrap();
    res
}

async fn copy_fragment<R: Read + Unpin, W: Write + Unpin>(m: usize, mut src: R, mut dst: W) {
    let mut buf = vec![0; m];
    while let Ok(n) = src.read(&mut buf).await {
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await.unwrap();
    }
}

// Run function `op`(a_rd, a_wr, b_rd, b_wr) where (a_rd, a_wr) is the one read/write end of a stream
// and (b_rd, b_wr) is the other read/write end of the same stream.  All the messages that pass
// through this stream are fragmented to a size of `n`.
pub async fn net_fragment<O, F, T>(n: usize, op: O) -> T
where
    O: FnOnce(UnixStream, UnixStream, UnixStream, UnixStream) -> F,
    F: Future<Output = T>,
{
    let (mut stream_a, mut stream_a_net) = std::os::unix::net::UnixStream::pair().unwrap();
    let (mut stream_b, mut stream_b_net) = std::os::unix::net::UnixStream::pair().unwrap();
    for stream in &[
        &mut stream_a,
        &mut stream_b,
        &mut stream_a_net,
        &mut stream_b_net,
    ] {
        stream.set_read_timeout(Some(Duration::new(5, 0))).unwrap();
    }
    let stream_a_read = UnixStream::from(stream_a.try_clone().unwrap());
    let stream_a_write = UnixStream::from(stream_a.try_clone().unwrap());
    let stream_b_read = UnixStream::from(stream_b.try_clone().unwrap());
    let stream_b_write = UnixStream::from(stream_b.try_clone().unwrap());
    let stream_a_net_cpy = UnixStream::from(stream_a_net.try_clone().unwrap());
    let stream_b_net_cpy = UnixStream::from(stream_b_net.try_clone().unwrap());
    let stream_a_net = UnixStream::from(stream_a_net.try_clone().unwrap());
    let stream_b_net = UnixStream::from(stream_b_net.try_clone().unwrap());

    let future_a = copy_fragment(n, stream_a_net, stream_b_net);
    let future_b = copy_fragment(n + 1, stream_b_net_cpy, stream_a_net_cpy);
    let future_ab = future::join(future_a, future_b);
    let future_op = op(stream_a_read, stream_a_write, stream_b_read, stream_b_write);
    let (res, future_ab) = match future::select(Box::pin(future_op), Box::pin(future_ab)).await {
        Either::Left((res, future_ab)) => (res, future_ab),
        Either::Right((_, _future_op)) => panic!("net terminated before op"),
    };
    stream_a.shutdown(Shutdown::Both).unwrap();
    stream_b.shutdown(Shutdown::Both).unwrap();
    future_ab.await;
    res
}
