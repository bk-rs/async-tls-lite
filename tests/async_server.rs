use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;

use futures_executor::{block_on, ThreadPool};
use futures_util::task::SpawnExt;

mod helper;

mod inner_helper {
    use std::io;
    use std::net::TcpStream;
    use std::sync::mpsc::Sender;

    use async_io::Async;
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use rustls::ServerSession;

    use async_tls_lite::handshake;

    pub async fn run_async_server(
        server_session: ServerSession,
        tcp_stream: TcpStream,
        sender: Sender<String>,
    ) -> io::Result<()> {
        let tcp_stream = Async::<TcpStream>::new(tcp_stream)?;

        let mut tls_stream = handshake(server_session, tcp_stream).await?;

        let mut buf = [0; 5];
        tls_stream.read(&mut buf).await?;
        assert_eq!(&buf, b"foo\0\0");
        println!("server tls_stream read foo done");

        tls_stream.write(b"bar").await?;
        println!("server tls_stream write bar done");

        let mut buf = [0; 5];
        let n = tls_stream.read(&mut buf).await?;
        assert_eq!(n, 0);
        assert_eq!(&buf, b"\0\0\0\0\0");
        println!("server tls_stream read EOF done");

        sender
            .send("server_done".to_owned())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(())
    }
}

#[test]
fn tcp_stream() -> io::Result<()> {
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let mut client_session = helper::get_client_session()?;
        let server_session = helper::get_server_session()?;

        let mut tcp_stream_c = TcpStream::connect(addr)?;
        let tcp_stream_s = listener
            .incoming()
            .next()
            .expect("Get next incoming failed")?;

        println!(
            "addr {:?}, tcp_stream_c {:?} tcp_stream_s {:?}",
            addr, tcp_stream_c, tcp_stream_s
        );

        let (sender_s, receiver) = mpsc::channel::<String>();
        let sender_c = sender_s.clone();

        let executor = ThreadPool::new()?;

        executor
            .spawn(async move {
                inner_helper::run_async_server(server_session, tcp_stream_s, sender_s)
                    .await
                    .map_err(|err| {
                        eprintln!("run_async_server failed, err: {:?}", err);
                        err
                    })
                    .unwrap()
            })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        executor
            .spawn(async move {
                helper::run_sync_client(&mut client_session, &mut tcp_stream_c, sender_c)
                    .await
                    .map_err(|err| {
                        eprintln!("run_sync_client failed, err: {:?}", err);
                        err
                    })
                    .unwrap()
            })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let msg = receiver.recv().unwrap();
        println!("receiver.recv {}", msg);
        assert_eq!(msg, "client_done");

        let msg = receiver.recv().unwrap();
        println!("receiver.recv {}", msg);
        assert_eq!(msg, "server_done");

        Ok(())
    })
}
