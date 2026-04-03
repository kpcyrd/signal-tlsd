mod readahead;
mod rules;

use crate::readahead::ReadAhead;
use crate::rules::Rules;
use anyhow::{Context, Result};
use clap::{ArgAction, Parser};
use env_logger::Env;
use log::{debug, info, warn};
use std::sync::Arc;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};
use tokio_rustls::rustls;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

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
}

async fn accept<S: AsyncRead + AsyncWrite + Unpin>(stream: S, rules: &Rules) {
    let acceptor = tokio_rustls::LazyConfigAcceptor::new(
        rustls::server::Acceptor::default(),
        ReadAhead::new(stream),
    );
    tokio::pin!(acceptor);

    let (server_name, stream) = match acceptor.as_mut().await {
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

    if !rules.allowed(&server_name) {
        info!("Rejecting connection request, destination not allowed: {server_name:?}");
        return;
    }

    let mut remote = match timeout(CONNECT_TIMEOUT, TcpStream::connect((server_name, 443))).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            warn!("Failed to connect to remote server: {err:#}");
            return;
        }
        Err(_) => {
            warn!("Timed out while connecting to remote server");
            return;
        }
    };
    debug!("Connected to remote server");

    let Ok(_) = remote.write_all(stream.buffered()).await else {
        warn!("Failed to forward buffered TLS client hello");
        return;
    };

    debug!("Flushed buffered data to remote server");
    if let Err(err) = io::copy_bidirectional(&mut stream.into_inner(), &mut remote).await {
        warn!("Error while forwarding connection: {err:#}");
    }

    debug!("Finished data forwarding");
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

    let rules = if !args.allow.is_empty() {
        Rules::from_iter(args.allow)
    } else {
        Rules::from_iter(rules::SIGNAL_HOSTS.iter().copied())
    };
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
                let (stream, _) = listener.accept().await.unwrap();
                let rules = rules.clone();

                tokio::spawn(async move {
                    debug!("Accepted new TCP connection");
                    accept(stream, &rules).await;
                    debug!("Connection has been closed");
                });
            }
        } => err,
        // Signal handling for pid1
        _ = sigterm() => Ok(()),
    }
}
