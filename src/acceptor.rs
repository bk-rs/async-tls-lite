// ref https://github.com/async-rs/async-tls/blob/v0.7.1/src/acceptor.rs

use std::io;
use std::sync::Arc;

use futures_util::io::{AsyncRead, AsyncWrite};
use rustls::{ServerConfig, ServerSession};

use crate::{handshake, TlsStream};

#[derive(Clone)]
pub struct TlsAcceptor {
    inner: Arc<ServerConfig>,
}

impl From<Arc<ServerConfig>> for TlsAcceptor {
    fn from(inner: Arc<ServerConfig>) -> TlsAcceptor {
        TlsAcceptor { inner }
    }
}

impl TlsAcceptor {
    pub async fn accept<IO>(&self, stream: IO) -> io::Result<TlsStream<ServerSession, IO>>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let session = ServerSession::new(&self.inner);

        handshake(session, stream).await
    }
}
