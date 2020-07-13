use std::env;
use std::fs::File;
use std::io::{self, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::str;
use std::sync::Arc;

use futures::StreamExt;
use futures::{AsyncReadExt, AsyncWriteExt};
use smol::{Async, Task};

use async_tls_lite::prelude::{pemfile, NoClientAuth, ServerConfig};
use async_tls_lite::TlsAcceptor;

/*
curl https://tls.lvh.me:443/ -v -k
curl https://tls.lvh.me:443/ -v --cacert mkcert/rootCA.pem
*/

fn main() -> io::Result<()> {
    smol::run(run())
}

async fn run() -> io::Result<()> {
    let mut server_config = ServerConfig::new(NoClientAuth::new());

    let mkcert_path = PathBuf::new().join("mkcert");
    let certs = pemfile::certs(&mut BufReader::new(File::open(
        mkcert_path.join("tls.lvh.me.crt"),
    )?))
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;
    let key = pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(
        mkcert_path.join("tls.lvh.me-key.pem"),
    )?))
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))?
    .first()
    .expect("invalid key")
    .to_owned();
    server_config
        .set_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    //
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let port: u16 = env::var("LISTEN_PORT")
        .unwrap_or_else(|_| "443".to_owned())
        .parse()
        .unwrap();
    let listener = Async::<TcpListener>::bind(format!("127.0.0.1:{}", port))?;

    let mut incoming = listener.incoming();
    while let Some(tcp_stream) = incoming.next().await {
        let acceptor = acceptor.clone();

        let task = Task::<io::Result<()>>::spawn(async move {
            let tcp_stream = tcp_stream?;
            println!("Accepted client: {}", tcp_stream.get_ref().peer_addr()?);

            let mut tls_stream = acceptor.accept(tcp_stream).await?;

            let mut buf = vec![0; 64];
            tls_stream.read(&mut buf).await?;

            println!("{:?}", str::from_utf8(&buf));

            if buf.starts_with(b"GET / HTTP/1.1\r\n") {
                tls_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
            } else {
                tls_stream
                    .write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    .await?;
            }

            Ok(())
        });

        Task::spawn(async move {
            task.await
                .unwrap_or_else(|err| eprintln!("handle failed, err: {:?}", err));
        })
        .detach()
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{SocketAddr, TcpStream};
    use std::time::Duration;

    use smol::Timer;

    use async_tls_lite::prelude::{ClientConfig, TLS_SERVER_ROOTS};
    use async_tls_lite::TlsConnector;

    #[test]
    fn sample() -> io::Result<()> {
        smol::run(async {
            let listen_port = find_listen_addr().port();

            let server = Task::<io::Result<()>>::spawn(async move {
                env::set_var("LISTEN_PORT", format!("{}", listen_port));

                run().await?;

                Ok(())
            });

            let client = Task::<io::Result<()>>::spawn(async move {
                Timer::after(Duration::from_millis(300)).await;

                let mut client_config = ClientConfig::new();

                let mkcert_path = PathBuf::new().join("mkcert");
                client_config
                    .root_store
                    .add_server_trust_anchors(&TLS_SERVER_ROOTS);
                client_config
                    .root_store
                    .add_pem_file(&mut BufReader::new(File::open(
                        mkcert_path.join("rootCA.pem"),
                    )?))
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;

                //
                let tcp_stream =
                    Async::<TcpStream>::connect(format!("127.0.0.1:{}", listen_port)).await?;
                let connector = TlsConnector::from(Arc::new(client_config.clone()));
                let mut tls_stream = connector.connect("tls.lvh.me", tcp_stream).await?;

                tls_stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await?;
                let mut buf = vec![0; 64];
                tls_stream.read(&mut buf).await?;
                println!("{:?}", str::from_utf8(&buf));
                assert!(buf.starts_with(b"HTTP/1.1 200 OK\r\n\r\n"));

                //
                let tcp_stream =
                    Async::<TcpStream>::connect(format!("127.0.0.1:{}", listen_port)).await?;
                let connector = TlsConnector::from(Arc::new(client_config));
                let mut tls_stream = connector.connect("tls.lvh.me", tcp_stream).await?;

                tls_stream.write_all(b"GET /foo HTTP/1.1\r\n\r\n").await?;
                let mut buf = vec![0; 64];
                tls_stream.read(&mut buf).await?;
                println!("{:?}", str::from_utf8(&buf));
                assert!(buf.starts_with(b"HTTP/1.1 400 Bad Request\r\n\r\n"));

                Ok(())
            });

            client.await?;
            server.cancel().await;

            Ok(())
        })
    }

    fn find_listen_addr() -> SocketAddr {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }
}
