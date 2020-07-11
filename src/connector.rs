// ref https://github.com/async-rs/async-tls/blob/v0.7.1/src/connector.rs

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use futures_util::io::{AsyncRead, AsyncWrite};
use rustls::{ClientConfig, ClientSession};
use webpki::DNSNameRef;

use crate::{handshake, MidHandshake, TlsStream};

#[derive(Clone)]
pub struct TlsConnector {
    inner: Arc<ClientConfig>,
}

impl From<Arc<ClientConfig>> for TlsConnector {
    fn from(inner: Arc<ClientConfig>) -> TlsConnector {
        TlsConnector { inner }
    }
}

impl Default for TlsConnector {
    fn default() -> Self {
        let mut config = ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        Arc::new(config).into()
    }
}

impl TlsConnector {
    pub fn new() -> Self {
        Default::default()
    }

    pub fn connect<IO>(&self, domain: impl AsRef<str>, stream: IO) -> Connect<IO> {
        let domain = match DNSNameRef::try_from_ascii_str(domain.as_ref()) {
            Ok(domain) => domain,
            Err(_) => {
                return Connect(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid domain",
                )));
            }
        };

        let session = ClientSession::new(&self.inner, domain);

        Connect(Ok(handshake(session, stream)))
    }
}

pub struct Connect<IO>(io::Result<MidHandshake<ClientSession, IO>>);

impl<IO> Future for Connect<IO>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<TlsStream<ClientSession, IO>>;

    #[inline]
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        match self.0 {
            Ok(ref mut mid_handshake) => Pin::new(mid_handshake).poll(cx),
            Err(ref err) => Poll::Ready(Err(io::Error::new(err.kind(), err.to_string()))),
        }
    }
}
