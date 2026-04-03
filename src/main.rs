use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use env_logger::Env;
use log::{debug, info, warn};
use std::collections::BTreeSet;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Poll;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_rustls::rustls;

// List taken from https://github.com/signalapp/Signal-TLS-Proxy/blob/main/data/nginx-relay/nginx.conf
const SIGNAL_HOSTS: &[&str] = &[
    "chat.signal.org",
    "storage.signal.org",
    "cdn.signal.org",
    "cdn2.signal.org",
    "cdn3.signal.org",
    "cdsi.signal.org",
    "contentproxy.signal.org",
    "grpc.chat.signal.org",
    "sfu.voip.signal.org",
    "svr2.signal.org",
    "svrb.signal.org",
    "updates.signal.org",
    "updates2.signal.org",
];

const BUF_SIZE: usize = 1 << 14;

#[derive(Parser)]
#[command(version, override_usage = env!("CARGO_BIN_NAME"))]
struct Args {
    /// Increase log level (can be set multiple times)
    #[arg(short = 'v', long = "verbose", action(ArgAction::Count))]
    verbose: u8,
    /// Decrease log level (twice to fully turn off error logging too)
    #[arg(short = 'q', long = "quiet", action(ArgAction::Count))]
    quiet: u8,
    /// Address to bind to
    #[arg(
        short = 'B',
        long = "bind",
        default_value = "127.0.0.1:4443",
        env = "BIND_ADDR"
    )]
    bind: String,
}

struct ReadAhead<S> {
    stream: S,
    buf: [u8; BUF_SIZE],
    cursor: usize,
}

impl<S> ReadAhead<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            buf: [0; BUF_SIZE],
            cursor: 0,
        }
    }

    fn buffered(&self) -> &[u8] {
        &self.buf[..self.cursor]
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
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
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

async fn accept<S: AsyncRead + AsyncWrite + Unpin>(stream: S, rules: &BTreeSet<&'static str>) {
    let acceptor = tokio_rustls::LazyConfigAcceptor::new(
        rustls::server::Acceptor::default(),
        ReadAhead::new(stream),
    );
    tokio::pin!(acceptor);

    let (server_name, mut stream) = match acceptor.as_mut().await {
        Ok(start) => {
            let client_hello = start.client_hello();
            let Some(server_name) = client_hello.server_name() else {
                debug!("TLS client hello with no server name");
                return;
            };
            (server_name.to_string(), start.io)
        }
        Err(err) => {
            debug!("Failed to read TLS client hello: {err:#}");
            return;
        }
    };

    info!("Received TLS client hello for server name: {server_name:?}");
    debug!("Buffered {} bytes of client hello", stream.buffered().len());

    if !rules.contains(server_name.as_str()) {
        info!("Rejecting connection request, destination not allowed: {server_name:?}");
        return;
    }

    let Ok(mut remote) = TcpStream::connect((server_name, 443)).await else {
        warn!("Failed to connect to remote server");
        return;
    };
    debug!("Connected to remote server");

    let Ok(_) = remote.write_all(stream.buffered()).await else {
        warn!("Failed to forward buffered TLS client hello");
        return;
    };

    debug!("Flushed buffered data to remote server");
    if let Err(err) = io::copy_bidirectional(&mut stream.stream, &mut remote).await {
        warn!("Error while forwarding connection: {err:#}");
    }

    debug!("Connection has been closed");
}

// Handle shutdown signals so we can run this as pid1
async fn sigterm() {
    let mut set = JoinSet::new();
    // On ctrl-c, shutdown
    set.spawn(async {
        let _ = tokio::signal::ctrl_c().await;
    });

    #[cfg(unix)]
    {
        // On SIGTERM, shutdown
        use tokio::signal::unix;
        if let Ok(mut signal) = unix::signal(unix::SignalKind::terminate()) {
            set.spawn(async move {
                signal.recv().await;
            });
        }
    }

    set.join_next().await;
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = match (args.quiet, args.verbose) {
        (0, 0) => "info",
        (0, 1) => "debug",
        (0, _) => "trace",
        (1, _) => "warn",
        _ => "off",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    let rules = Arc::new(BTreeSet::from_iter(SIGNAL_HOSTS.iter().copied()));

    tokio::select! {
        // The main daemon
        err = async {
            info!("Binding to address: {:?}", args.bind);
            let listener = TcpListener::bind(&args.bind)
                .await
                .with_context(|| format!("Failed to bind to address: {:?}", args.bind))?;
            info!("Listening for connections...");
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let rules = rules.clone();

                tokio::spawn(async move {
                    accept(stream, &rules).await;
                });
            }
        } => err,
        // Signal handling for pid1
        _ = sigterm() => Ok(()),
    }
}
