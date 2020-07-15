use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;

use futures_executor::{block_on, ThreadPool};
use futures_util::task::SpawnExt;

mod helper;

mod inner_helper {
    use std::io;
    use std::net::{Shutdown, TcpStream};
    use std::sync::mpsc::Sender;

    use async_io::Async;
    use futures_util::io::{AsyncReadExt, AsyncWriteExt};
    use rustls::ClientSession;

    use async_tls_lite::client_handshake;

    pub async fn run_async_client(
        client_session: ClientSession,
        tcp_stream: TcpStream,
        sender: Sender<String>,
    ) -> io::Result<()> {
        let tcp_stream = Async::<TcpStream>::new(tcp_stream)?;

        let mut tls_stream = client_handshake(client_session, tcp_stream).await?;

        tls_stream.write(b"foo").await?;
        println!("client tls_stream write foo done");
        let mut buf = [0; 5];
        tls_stream.read(&mut buf).await?;
        assert_eq!(&buf, b"bar\0\0");
        println!("client tls_stream read bar done");

        let tcp_stream = tls_stream.get_mut();
        tcp_stream.get_mut().shutdown(Shutdown::Both)?;

        println!("client tls_stream shutdown done");
        sender
            .send("client_done".to_owned())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(())
    }
}

#[test]
fn tcp_stream() -> io::Result<()> {
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let client_session = helper::get_client_session()?;
        let mut server_session = helper::get_server_session()?;

        let tcp_stream_c = TcpStream::connect(addr)?;
        let mut tcp_stream_s = listener
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
                helper::run_sync_server(&mut server_session, &mut tcp_stream_s, sender_s)
                    .await
                    .map_err(|err| {
                        eprintln!("run_sync_server failed, err: {:?}", err);
                        err
                    })
                    .unwrap()
            })
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        executor
            .spawn(async move {
                inner_helper::run_async_client(client_session, tcp_stream_c, sender_c)
                    .await
                    .map_err(|err| {
                        eprintln!("run_async_client failed, err: {:?}", err);
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
