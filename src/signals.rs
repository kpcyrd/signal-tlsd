use crate::errors::*;
use crate::tls::Tls;
use std::future;
use tokio::task::JoinSet;

// Handle shutdown signals so we can run this as pid1
pub async fn sigterm() {
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

pub async fn sighup(tls: Option<&Tls>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix;
        if let Ok(mut signals) = unix::signal(unix::SignalKind::hangup()) {
            while signals.recv().await.is_some() {
                if let Some(tls) = tls {
                    info!("Received SIGHUP, reloading TLS certificate");
                    if let Err(err) = tls.reload().await {
                        warn!("Failed to reload TLS certificate: {err:#}");
                    } else {
                        debug!("TLS certificate reloaded successfully");
                    }
                }
            }
        }
    }

    // Reload signals not supported, wait indefinitely
    future::pending().await
}
