use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;

use futures_executor::{block_on, ThreadPool};
use futures_util::task::SpawnExt;

mod helper;

#[test]
fn tcp_stream() -> io::Result<()> {
    block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let addr = listener.local_addr()?;

        let mut client_session = helper::get_client_session()?;
        let mut server_session = helper::get_server_session()?;

        let mut tcp_stream_c = TcpStream::connect(addr)?;
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
                helper::run_sync_client(&mut client_session, &mut tcp_stream_c, sender_c)
                    .await
                    .map_err(|err| {
                        eprintln!("run_sync_server failed, err: {:?}", err);
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
