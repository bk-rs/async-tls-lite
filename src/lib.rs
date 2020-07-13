use std::future::Future;
use std::io::{self, Read, Write};
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_io_traits_sync_wrapper::Wrapper as AsyncRWSyncWrapper;
use futures_util::io::{AsyncRead, AsyncWrite};
use rustls::{Session, Stream};

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

pub struct TlsStream<S, IO> {
    session: S,
    io: Box<IO>,
}

impl<S, IO> TlsStream<S, IO> {
    pub fn get_mut(&mut self) -> (&mut S, &mut IO) {
        (&mut self.session, self.io.as_mut())
    }

    pub fn get_ref(&self) -> (&S, &IO) {
        (&self.session, self.io.as_ref())
    }

    pub fn into_inner(self) -> (S, IO) {
        (self.session, *self.io)
    }
}

pub async fn handshake<S, IO>(session: S, io: IO) -> io::Result<TlsStream<S, IO>>
where
    S: Session + Unpin,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    Handshake(Some((session, io))).await
}

struct Handshake<S, IO>(Option<(S, IO)>);

impl<S, IO> Future for Handshake<S, IO>
where
    S: Session + Unpin,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<TlsStream<S, IO>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        let (mut session, mut stream) = this.0.take().expect("never");

        let mut io = AsyncRWSyncWrapper::new(&mut stream, cx);

        match session.complete_io(&mut io) {
            Ok(_) => Poll::Ready(Ok(TlsStream {
                session,
                io: Box::new(stream),
            })),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                this.0 = Some((session, stream));

                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl<S, IO> AsyncRead for TlsStream<S, IO>
where
    S: Session + Unpin,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        let mut io = AsyncRWSyncWrapper::new(&mut this.io, cx);

        let mut stream = Stream::new(&mut this.session, &mut io);

        match stream.read(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
        }
    }
}

impl<S, IO> AsyncWrite for TlsStream<S, IO>
where
    S: Session + Unpin,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context, buf: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        let mut io = AsyncRWSyncWrapper::new(&mut this.io, cx);

        let mut stream = Stream::new(&mut this.session, &mut io);

        match stream.write(buf) {
            Ok(n) => Poll::Ready(Ok(n)),
            Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => Poll::Pending,
            Err(err) => Poll::Ready(Err(err)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        let mut io = AsyncRWSyncWrapper::new(&mut this.io, cx);

        let mut stream = Stream::new(&mut this.session, &mut io);

        stream.flush()?;

        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        Pin::new(&mut this.io).poll_close(cx)
    }
}
