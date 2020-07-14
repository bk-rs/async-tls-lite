use std::io;
use std::net::TcpStream;
use std::str;
use std::thread;
use std::time::Duration;

use futures::future;
use futures::select;
use futures::FutureExt;
use futures::{AsyncReadExt, AsyncWriteExt};
use smol::{Async, Task, Timer};

use async_tls_lite::TlsConnector;

fn main() -> io::Result<()> {
    thread::spawn(|| smol::run(future::pending::<()>()));
    thread::spawn(|| smol::run(future::pending::<()>()));

    smol::block_on(run())
}

async fn run() -> io::Result<()> {
    let mut receivers = vec![];

    for i in 0..=10 {
        let (sender, receiver) = async_channel::unbounded();
        receivers.push(receiver);

        let task = Task::<io::Result<()>>::spawn(async move {
            let tcp_stream = select! {
                ret = Async::<TcpStream>::connect("github.com:443").fuse() => ret,
                _ = Timer::after(Duration::from_millis(500)).fuse() => Err(io::Error::new(io::ErrorKind::TimedOut, "connect timeout")),
            }?;
            let tcp_stream = tcp_stream.into_inner()?;
            tcp_stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            tcp_stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            let tcp_stream = Async::new(tcp_stream)?;

            let connector = TlsConnector::default();

            let mut tls_stream = connector.connect("github.com", tcp_stream).await?;

            tls_stream
                .write_all(
                    br#"
GET / HTTP/1.1
Host: github.com
user-agent: curl/7.71.1
accept: */*

        "#,
                )
                .await?;

            let mut buf = vec![0; 64];
            tls_stream.read(&mut buf).await?;

            println!("{} {:?}", i, str::from_utf8(&buf));

            Ok(())
        });

        Task::spawn(async move {
            task.await
                .unwrap_or_else(|err| eprintln!("task {} failed, err: {}", i, err));

            sender.send(format!("{} done", i)).await.unwrap()
        })
        .detach();
    }

    for receiver in receivers {
        let msg = receiver.recv().await.unwrap();
        println!("{}", msg);
    }

    Ok(())
}
