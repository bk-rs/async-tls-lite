use std::future::Future;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_io_traits_sync_wrapper::Wrapper as AsyncRWSyncWrapper;
use futures_util::io::{AsyncRead, AsyncWrite};
use rustls::{ClientSession, ServerSession, Session, Stream};

#[cfg(feature = "acceptor")]
mod acceptor;
#[cfg(feature = "acceptor")]
pub use acceptor::TlsAcceptor;

#[cfg(feature = "connector")]
mod connector;
#[cfg(feature = "connector")]
pub use connector::TlsConnector;

pub mod prelude {
    pub use rustls::{
        internal::pemfile, ClientConfig, ClientSession, NoClientAuth, ServerConfig, ServerSession,
        Session as RustlsSession,
    };

    #[cfg(feature = "connector")]
    pub use webpki::DNSNameRef;
    #[cfg(feature = "connector")]
    pub use webpki_roots::TLS_SERVER_ROOTS;
}

pub struct TlsStream<SESS, S> {
    inner: TlsStreamInner<SESS, S>,
}

struct TlsStreamInner<SESS, S> {
    session: SESS,
    stream: S,
}

impl<SESS, S> TlsStream<SESS, S> {
    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner.stream
    }

    pub fn get_ref(&self) -> &S {
        &self.inner.stream
    }

    pub fn get_session_mut(&mut self) -> &mut SESS {
        &mut self.inner.session
    }

    pub fn get_session_ref(&self) -> &SESS {
        &self.inner.session
    }
}

pub async fn client_handshake<S>(
    session: ClientSession,
    stream: S,
) -> io::Result<TlsStream<ClientSession, S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake(session, stream).await
}

pub async fn server_handshake<S>(
    session: ServerSession,
    stream: S,
) -> io::Result<TlsStream<ServerSession, S>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    handshake(session, stream).await
}

async fn handshake<SESS, S>(session: SESS, stream: S) -> io::Result<TlsStream<SESS, S>>
where
    SESS: Session + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    Handshake(Some((session, stream))).await
}

struct Handshake<SESS, S>(Option<(SESS, S)>);

impl<SESS, S> Future for Handshake<SESS, S>
where
    SESS: Session + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<TlsStream<SESS, S>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        let (mut session, mut stream) = this.0.take().expect("never");

        let mut sync_stream = AsyncRWSyncWrapper::new(&mut stream, cx);

        match session.complete_io(&mut sync_stream) {
            Ok(_) => Poll::Ready(Ok(TlsStream {
                inner: TlsStreamInner { session, stream },
            })),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                this.0 = Some((session, stream));

                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl<SESS, S> AsyncRead for TlsStream<SESS, S>
where
    SESS: Session + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        let mut sync_stream = AsyncRWSyncWrapper::new(&mut this.inner.stream, cx);

        let mut rustls_stream = Stream::new(&mut this.inner.session, &mut sync_stream);

        match rustls_stream.read(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl<SESS, S> AsyncWrite for TlsStream<SESS, S>
where
    SESS: Session + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        let mut sync_stream = AsyncRWSyncWrapper::new(&mut this.inner.stream, cx);

        let mut rustls_stream = Stream::new(&mut this.inner.session, &mut sync_stream);

        match rustls_stream.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        let mut sync_stream = AsyncRWSyncWrapper::new(&mut this.inner.stream, cx);

        let mut rustls_stream = Stream::new(&mut this.inner.session, &mut sync_stream);

        rustls_stream.flush()?;

        Pin::new(&mut this.inner.stream).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        Pin::new(&mut this.inner.stream).poll_close(cx)
    }
}
