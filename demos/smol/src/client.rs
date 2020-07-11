use std::io;
use std::net::TcpStream;
use std::str;
use std::thread;

use futures::future;
use futures::{AsyncReadExt, AsyncWriteExt};
use smol::{Async, Task};

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

        let task: Task<io::Result<()>> = Task::spawn(async move {
            let tcp_stream = Async::<TcpStream>::connect("github.com:443").await?;

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

            sender.send(format!("{} done", i)).await.unwrap();

            Ok(())
        });

        task.expect("").detach();
    }

    for receiver in receivers {
        let msg = receiver.recv().await.unwrap();
        println!("{}", msg);
    }

    Ok(())
}
