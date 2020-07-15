// ref https://github.com/async-rs/async-tls/blob/v0.7.1/src/connector.rs

use std::io;
use std::sync::Arc;

use futures_util::io::{AsyncRead, AsyncWrite};
use rustls::{ClientConfig, ClientSession};
use webpki::DNSNameRef;

use crate::{client_handshake, TlsStream};

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

    pub async fn connect<S>(
        &self,
        domain: impl AsRef<str>,
        stream: S,
    ) -> io::Result<TlsStream<ClientSession, S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let domain = match DNSNameRef::try_from_ascii_str(domain.as_ref()) {
            Ok(domain) => domain,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "invalid domain",
                ));
            }
        };

        let session = ClientSession::new(&self.inner, domain);

        client_handshake(session, stream).await
    }
}
