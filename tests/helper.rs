use std::fs::File;
use std::io::{self, BufReader, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::path::PathBuf;
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use rustls::{
    internal::pemfile, ClientConfig, ClientSession, NoClientAuth, ServerConfig, ServerSession,
    Session, Stream,
};
use webpki::DNSNameRef;
use webpki_roots::TLS_SERVER_ROOTS;

pub fn get_client_session() -> io::Result<ClientSession> {
    let mut client_config = ClientConfig::new();

    let mkcert_path = get_mkcert_path();
    client_config
        .root_store
        .add_server_trust_anchors(&TLS_SERVER_ROOTS);
    client_config
        .root_store
        .add_pem_file(&mut BufReader::new(File::open(
            mkcert_path.join("rootCA.pem"),
        )?))
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid cert"))?;

    let client_session = ClientSession::new(
        &Arc::new(client_config),
        DNSNameRef::try_from_ascii_str("tls.lvh.me").unwrap(),
    );

    Ok(client_session)
}

pub fn get_server_session() -> io::Result<ServerSession> {
    let mut server_config = ServerConfig::new(NoClientAuth::new());

    let mkcert_path = get_mkcert_path();
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

    let server_session = ServerSession::new(&Arc::new(server_config));

    Ok(server_session)
}

#[allow(dead_code)]
pub async fn run_sync_server(
    server_session: &mut ServerSession,
    tcp_stream: &mut TcpStream,
    sender: Sender<String>,
) -> io::Result<()> {
    server_session
        .complete_io(tcp_stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut tls_stream = Stream::new(server_session, tcp_stream);

    let mut buf = [0; 5];
    tls_stream.read(&mut buf)?;
    assert_eq!(&buf, b"foo\0\0");
    println!("server tls_stream read foo done");

    tls_stream.write(b"bar")?;
    println!("server tls_stream write bar done");

    thread::sleep(Duration::from_millis(100));

    let mut buf = [0; 5];
    let n = tls_stream.read(&mut buf)?;
    assert_eq!(n, 0);
    assert_eq!(&buf, b"\0\0\0\0\0");
    println!("server tls_stream read EOF done");

    sender
        .send("server_done".to_owned())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(())
}

#[allow(dead_code)]
pub async fn run_sync_client(
    client_session: &mut ClientSession,
    tcp_stream: &mut TcpStream,
    sender: Sender<String>,
) -> io::Result<()> {
    client_session
        .complete_io(tcp_stream)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let mut tls_stream = Stream::new(client_session, tcp_stream);

    tls_stream.write(b"foo")?;
    println!("client tls_stream write foo done");

    let mut buf = [0; 5];
    tls_stream.read(&mut buf)?;
    assert_eq!(&buf, b"bar\0\0");
    println!("client tls_stream read bar done");

    tls_stream.sock.shutdown(Shutdown::Both)?;
    println!("client tls_stream shutdown done");

    sender
        .send("client_done".to_owned())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    Ok(())
}

fn get_mkcert_path() -> PathBuf {
    PathBuf::new().join("mkcert")
}
