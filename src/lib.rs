use std::future::Future;
use std::io::{self, Read, Write};
use std::mem;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_io_traits_sync_wrapper::Wrapper as AsyncRWSyncWrapper;
use futures_util::io::{AsyncRead, AsyncWrite};
use rustls::{Session, Stream};

#[cfg(feature = "acceptor")]
mod acceptor;
#[cfg(feature = "acceptor")]
pub use acceptor::{Accept, TlsAcceptor};

#[cfg(feature = "connector")]
mod connector;
#[cfg(feature = "connector")]
pub use connector::{Connect, TlsConnector};

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

#[derive(PartialEq, Eq)]
enum State {
    Pending,
    HandshakeCompleted,
}

pub struct TlsStream<S, IO> {
    session: S,
    io: Box<IO>,
    state: State,
}

impl<S, IO> TlsStream<S, IO> {
    fn new(session: S, io: IO) -> Self {
        Self {
            session,
            io: Box::new(io),
            state: State::Pending,
        }
    }

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

pub enum MidHandshake<S, IO> {
    Handshaking(TlsStream<S, IO>),
    End,
}

pub fn handshake<S, IO>(session: S, io: IO) -> MidHandshake<S, IO> {
    MidHandshake::Handshaking(TlsStream::new(session, io))
}

impl<S, IO> Future for MidHandshake<S, IO>
where
    S: Session + Unpin,
    IO: AsyncRead + AsyncWrite + Unpin,
{
    type Output = io::Result<TlsStream<S, IO>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        if let MidHandshake::Handshaking(tls_stream) = this {
            let mut io = AsyncRWSyncWrapper::new(&mut tls_stream.io, cx);

            match tls_stream.session.complete_io(&mut io) {
                Ok(_) => {}
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Poll::Pending,
                Err(err) => return Poll::Ready(Err(err)),
            }
        }

        match mem::replace(this, MidHandshake::End) {
            MidHandshake::Handshaking(mut tls_stream) => {
                *this = MidHandshake::End;

                tls_stream.state = State::HandshakeCompleted;
                Poll::Ready(Ok(tls_stream))
            }
            MidHandshake::End => panic!(),
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

        debug_assert!(this.state == State::HandshakeCompleted);

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

        debug_assert!(this.state == State::HandshakeCompleted);

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
