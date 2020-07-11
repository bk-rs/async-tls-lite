// ref https://github.com/async-rs/async-tls/blob/v0.7.1/src/acceptor.rs

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::io::{AsyncRead, AsyncWrite};
use rustls::{ServerConfig, ServerSession};

use crate::{handshake, MidHandshake, TlsStream};

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
    #[inline]
    pub fn accept<IO>(&self, stream: IO) -> Accept<IO> {
        let session = ServerSession::new(&self.inner);

        Accept(handshake(session, stream))
    }
}

pub struct Accept<IO>(MidHandshake<ServerSession, IO>);

impl<IO> Future for Accept<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<TlsStream<ServerSession, IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        Pin::new(&mut self.0).poll(cx)
    }
}
