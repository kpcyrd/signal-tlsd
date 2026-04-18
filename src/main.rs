mod errors;
mod readahead;
mod rules;
mod signals;
mod tls;

use crate::errors::*;
use crate::readahead::ReadAhead;
use crate::rules::Rules;
use crate::tls::Tls;
use clap::{ArgAction, Parser};
use env_logger::Env;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
use tokio::sync::Notify;
use tokio::time::{Duration, timeout};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{self, ServerConfig};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(600);

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
    #[arg(short = 'A', long = "allow")]
    allow: Vec<String>,
    /// Fallback destination if inner connection isn't TLS, or the SNI value is not on allowlist (<ip>:<port>)
    #[arg(short = 'F', long = "fallback", env = "SIGNAL_TLSD_FALLBACK_ADDR")]
    fallback: Option<String>,
    /// Do not expect an outer TLS layer, assume the outer TLS layer has already been terminated
    #[arg(short = 'N')]
    no_tls: bool,
    /// Path to TLS certificate for outer TLS layer (PEM format)
    #[arg(long = "cert", env = "TLS_CERT_PATH")]
    cert: Option<PathBuf>,
    /// Path to TLS private key for outer TLS layer (PEM format)
    #[arg(long = "private-key", env = "TLS_PRIVATE_KEY_PATH")]
    private_key: Option<PathBuf>,
}

async fn connect<A: ToSocketAddrs>(addr: A) -> Result<TcpStream> {
    timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("connection timed out")?
        .map_err(Error::from)
}

async fn forward<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    notify: &Notify,
) -> io::Result<()> {
    let mut buffer = [0u8; 8192];
    let ret = loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break Ok(()), // EOF
            Ok(n) => {
                writer.write_all(&buffer[..n]).await?;
                writer.flush().await?;
                notify.notify_one();
            }
            Err(err) => break Err(err),
        }
    };
    writer.shutdown().await.ok();
    ret
}

async fn forward_bidirectional<C: AsyncReadWrite, U: AsyncReadWrite>(
    port: u16,
    client: C,
    upstream: U,
) -> io::Result<()> {
    let (client_read, client_write) = io::split(client);
    let (upstream_read, upstream_write) = io::split(upstream);

    let notify = Notify::new();

    tokio::select! {
        // Forward client <-> upstream
        ret = async {
            let (client, upstream) = tokio::join!(
                forward(client_read, upstream_write, &notify),
                forward(upstream_read, client_write, &notify),
            );
            client?;
            upstream?;
            Ok(())
        } => ret,
        // Expire the connection if idle for too long
        _ = async {
            loop {
                if timeout(IDLE_TIMEOUT, notify.notified()).await.is_err() {
                    debug!("X.X.X.X:{port}: Connection idle for too long, shutting down");
                    break;
                }
            }
        } => Ok(()),
    }
}

// Allow dynamic dispatch of TLS and non-TLS stream
trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

async fn accept<S: AsyncReadWrite>(
    stream: S,
    port: u16,
    tls_config: Option<Arc<ServerConfig>>,
    rules: &Rules,
) {
    // If enabled, perform outer TLS handshake
    let stream: Box<dyn AsyncReadWrite> = if let Some(config) = tls_config {
        let acceptor = TlsAcceptor::from(config);
        match timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
            Ok(Ok(stream)) => {
                debug!("X.X.X.X:{port}: Completed outer TLS handshake");
                Box::new(stream)
            }
            Ok(Err(err)) => {
                debug!("X.X.X.X:{port}: Failed to accept outer TLS connection: {err:#}");
                return;
            }
            Err(_) => {
                debug!("X.X.X.X:{port}: Outer TLS handshake timed out");
                return;
            }
        }
    } else {
        Box::new(stream)
    };

    // Read inner TLS client hello
    let acceptor = tokio_rustls::LazyConfigAcceptor::new(
        rustls::server::Acceptor::default(),
        ReadAhead::new(stream),
    );
    tokio::pin!(acceptor);

    let (server_name, stream) = match timeout(HANDSHAKE_TIMEOUT, acceptor.as_mut()).await {
        Ok(Ok(start)) => {
            let client_hello = start.client_hello();
            let Some(server_name) = client_hello.server_name() else {
                debug!("X.X.X.X:{port}: Received inner TLS client hello with no server name");
                return;
            };

            let server_name = server_name.to_string();
            let stream = start.io;
            info!(
                "X.X.X.X:{port}: Received inner TLS client hello for server name: {server_name:?}"
            );
            debug!(
                "X.X.X.X:{port}: Buffered {} bytes of inner TLS client hello",
                stream.buffered().len()
            );

            if rules.allowed(&server_name) {
                (Some(server_name), stream)
            } else {
                debug!(
                    "X.X.X.X:{port}: Rejecting connection request, destination not allowed: {server_name:?}"
                );
                (None, stream)
            }
        }
        Ok(Err(err)) => {
            if err.kind() == io::ErrorKind::UnexpectedEof {
                debug!(
                    "X.X.X.X:{port}: Connection closed before inner TLS client hello could be read"
                );
                return;
            }

            debug!("X.X.X.X:{port}: Failed to read inner TLS client hello: {err:#}");
            let Some(stream) = acceptor.take_io() else {
                return;
            };
            (None, stream)
        }
        Err(_) => {
            debug!("X.X.X.X:{port}: Inner TLS handshake timed out");
            return;
        }
    };

    // Setup remote connection
    let remote = if let Some(server_name) = server_name {
        connect((server_name, 443)).await
    } else if let Some(fallback) = rules.fallback() {
        debug!("X.X.X.X:{port}: Falling back to configured fallback destination: {fallback:?}");
        connect(fallback).await
    } else {
        return;
    };

    let mut remote = match remote {
        Ok(stream) => stream,
        Err(err) => {
            warn!("X.X.X.X:{port}: Failed to connect to remote server: {err:#}");
            return;
        }
    };
    debug!("X.X.X.X:{port}: Connected to remote server");

    let Ok(_) = remote.write_all(stream.buffered()).await else {
        warn!("X.X.X.X:{port}: Failed to forward buffered TLS client hello");
        return;
    };

    debug!("X.X.X.X:{port}: Flushed buffered data to remote server");
    if let Err(err) = forward_bidirectional(port, &mut stream.into_inner(), &mut remote).await {
        if err.kind() == io::ErrorKind::UnexpectedEof {
            // This is harmless, don't log as warning
            debug!("X.X.X.X:{port}: Unclean TLS shutdown by peer");
        } else {
            warn!("X.X.X.X:{port}: Error while forwarding connection: {err:#}");
            trace!("X.X.X.X:{port}: Verbose error: {err:?}");
        }
    }

    trace!("X.X.X.X:{port}: Finished data forwarding");
}

async fn setup_outer_tls_config(args: &Args) -> Result<Tls> {
    // Ensure necessary paths are configured
    let cert_file = args
        .cert
        .as_ref()
        .context("TLS certificate path must be provided when TLS is enabled")?;

    let private_key_file = args
        .private_key
        .as_ref()
        .context("TLS private key path must be provided when TLS is enabled")?;

    let tls_config = Tls::init(cert_file.clone(), private_key_file.clone()).await?;
    Ok(tls_config)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let log_level = match (args.quiet, args.verbose) {
        (0, 0) => "signal_tlsd=info",
        (0, 1) => "info,signal_tlsd=debug",
        (0, 2) => "debug,signal_tlsd=trace",
        (0, _) => "trace",
        (1, _) => "signal_tlsd=warn",
        _ => "off",
    };
    env_logger::init_from_env(Env::default().default_filter_or(log_level));

    // Load TLS certificate and private key
    let tls_config = if !args.no_tls {
        Some(setup_outer_tls_config(&args).await?)
    } else {
        None
    };

    // Setup forwarding rules
    let mut rules = if !args.allow.is_empty() {
        Rules::from_iter(args.allow)
    } else {
        Rules::from_iter(rules::SIGNAL_HOSTS.iter().copied())
    };
    rules.set_fallback(args.fallback);
    let rules = Arc::new(rules);

    tokio::select! {
        // The main daemon
        err = async {
            info!("Binding to address: {:?}", args.bind);
            let listener = TcpListener::bind(&args.bind)
                .await
                .with_context(|| format!("Failed to bind to address: {:?}", args.bind))?;

            info!("Listening for connections...");
            loop {
                let (stream, addr) = match listener.accept().await {
                    Ok(accept) => accept,
                    Err(err) => {
                        warn!("Failed to accept incoming connection: {err:#}");
                        continue;
                    },
                };
                let port = addr.port();
                let tls_config = tls_config.as_ref().map(Tls::rustls_config);
                let rules = rules.clone();

                tokio::spawn(async move {
                    debug!("X.X.X.X:{port}: Accepted new TCP connection");
                    accept(stream, port, tls_config, &rules).await;
                    debug!("X.X.X.X:{port}: Connection has been closed");
                });
            }
        } => err,
        // SIGHUP for certificate reload
        _ = signals::sighup(tls_config.as_ref()) => Ok(()),
        // SIGTERM/SIGINT handling for pid1 compatibility
        _ = signals::sigterm() => Ok(()),
    }
}
