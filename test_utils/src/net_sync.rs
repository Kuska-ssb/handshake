use std::{
    io::{Read, Write},
    net::Shutdown,
    os::unix::net::UnixStream,
    time::Duration,
};

use crossbeam::thread;

// Run function `op`(a_rd, a_wr, b_rd, b_wr) where (a_rd, a_wr) is the one read/write end of a stream
// and (b_rd, b_wr) is the other read/write end of the same stream.
pub fn net<O>(op: O) -> ()
where
    O: FnOnce(&mut UnixStream, &mut UnixStream, &mut UnixStream, &mut UnixStream) -> (),
{
    let (mut stream_a, mut stream_b) = UnixStream::pair().unwrap();
    for stream in &[&mut stream_a, &mut stream_b] {
        stream.set_read_timeout(Some(Duration::new(5, 0))).unwrap();
    }
    let mut stream_a_read = stream_a.try_clone().unwrap();
    let mut stream_a_write = stream_a.try_clone().unwrap();
    let mut stream_b_read = stream_b.try_clone().unwrap();
    let mut stream_b_write = stream_b.try_clone().unwrap();
    op(
        &mut stream_a_read,
        &mut stream_a_write,
        &mut stream_b_read,
        &mut stream_b_write,
    );
    stream_a.shutdown(Shutdown::Both).unwrap();
    stream_b.shutdown(Shutdown::Both).unwrap();
}

// Run function `op`(a_rd, a_wr, b_rd, b_wr) where (a_rd, a_wr) is the one read/write end of a stream
// and (b_rd, b_wr) is the other read/write end of the same stream.  All the messages that pass
// through this stream are fragmented to a size of `n`.
pub fn net_fragment<O>(n: usize, op: O) -> ()
where
    O: FnOnce(&mut UnixStream, &mut UnixStream, &mut UnixStream, &mut UnixStream) -> (),
{
    let (mut stream_a, mut stream_a_net) = UnixStream::pair().unwrap();
    let (mut stream_b, mut stream_b_net) = UnixStream::pair().unwrap();
    for stream in &[
        &mut stream_a,
        &mut stream_b,
        &mut stream_a_net,
        &mut stream_b_net,
    ] {
        stream.set_read_timeout(Some(Duration::new(5, 0))).unwrap();
    }
    thread::scope(|s| {
        let mut stream_a_read = stream_a.try_clone().unwrap();
        let mut stream_a_write = stream_a.try_clone().unwrap();
        let mut stream_b_read = stream_b.try_clone().unwrap();
        let mut stream_b_write = stream_b.try_clone().unwrap();
        let mut stream_a_net_cpy = stream_a_net.try_clone().unwrap();
        let mut stream_b_net_cpy = stream_b_net.try_clone().unwrap();
        let handle_a = s.spawn(move |_| {
            let mut buf = vec![0; n];
            while let Ok(n) = stream_a_net.read(&mut buf) {
                if n == 0 {
                    break;
                }
                stream_b_net.write_all(&buf[..n]).unwrap();
            }
        });
        let handle_b = s.spawn(move |_| {
            let mut buf = vec![0; n];
            while let Ok(n) = stream_b_net_cpy.read(&mut buf) {
                if n == 0 {
                    break;
                }
                stream_a_net_cpy.write_all(&buf[..n]).unwrap();
            }
        });
        op(
            &mut stream_a_read,
            &mut stream_a_write,
            &mut stream_b_read,
            &mut stream_b_write,
        );
        stream_a.shutdown(Shutdown::Both).unwrap();
        stream_b.shutdown(Shutdown::Both).unwrap();
        handle_a.join().unwrap();
        handle_b.join().unwrap();
    })
    .unwrap();
}
