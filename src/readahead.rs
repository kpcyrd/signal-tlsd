use crate::errors::*;
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

const BUF_SIZE: usize = 1 << 14;

pub struct ReadAhead<S> {
    stream: S,
    buf: [u8; BUF_SIZE],
    cursor: usize,
}

impl<S> ReadAhead<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: [0; BUF_SIZE],
            cursor: 0,
        }
    }

    pub fn buffered(&self) -> &[u8] {
        &self.buf[..self.cursor]
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ReadAhead<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        if let Poll::Ready(x) = Pin::new(&mut self.stream).poll_read(cx, buf) {
            let buf = buf.filled();
            let new = &buf[before..];

            if !new.is_empty() {
                let cursor = self.cursor;
                let buffered = &mut self.buf[cursor..];
                let Some(dest) = buffered.get_mut(..new.len()) else {
                    return Poll::Ready(Err(io::Error::other("buffer full")));
                };
                dest.copy_from_slice(new);
                self.cursor += new.len();
            }

            Poll::Ready(x)
        } else {
            Poll::Pending
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReadAhead<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Do not allow writing any TLS handshake errors
        trace!("Intercepted attempted write of {} bytes", buf.len());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
