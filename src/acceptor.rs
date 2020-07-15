// ref https://github.com/async-rs/async-tls/blob/v0.7.1/src/acceptor.rs

use std::io;
use std::sync::Arc;

use futures_util::io::{AsyncRead, AsyncWrite};
use rustls::{ServerConfig, ServerSession};

use crate::{server_handshake, TlsStream};

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
    pub async fn accept<S>(&self, stream: S) -> io::Result<TlsStream<ServerSession, S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let session = ServerSession::new(&self.inner);

        server_handshake(session, stream).await
    }
}
