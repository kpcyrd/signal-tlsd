use crate::errors::*;
use arc_swap::ArcSwap;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};

pub struct Tls {
    pub config: ArcSwap<ServerConfig>,
    pub cert_file: PathBuf,
    pub private_key_file: PathBuf,
}

impl Tls {
    pub async fn init(cert_file: PathBuf, private_key_file: PathBuf) -> Result<Self> {
        let config = load_from_disk(&cert_file, &private_key_file).await?;
        Ok(Self {
            config: ArcSwap::new(Arc::new(config)),
            cert_file,
            private_key_file,
        })
    }

    pub fn rustls_config(&self) -> Arc<ServerConfig> {
        self.config.load_full()
    }

    pub async fn reload(&self) -> Result<()> {
        let new = load_from_disk(&self.cert_file, &self.private_key_file).await?;
        self.config.store(Arc::new(new));
        Ok(())
    }
}

pub async fn load_from_disk(cert_file: &Path, private_key_file: &Path) -> Result<ServerConfig> {
    // Read from disk
    let cert = fs::read(&cert_file)
        .await
        .with_context(|| format!("Failed to read TLS certificate file: {cert_file:?}"))?;

    let private_key = fs::read(&private_key_file)
        .await
        .with_context(|| format!("Failed to read TLS private key file: {private_key_file:?}"))?;

    // Parse file contents
    let certs = CertificateDer::pem_slice_iter(&cert)
        .map(|cert| cert.map_err(Error::from))
        .collect::<Result<Vec<_>>>()
        .with_context(|| format!("Failed to parse TLS certificate from PEM file: {cert_file:?}"))?;

    let private_key = PrivateKeyDer::from_pem_slice(&private_key).with_context(|| {
        format!("Failed to parse TLS private key from PEM file: {private_key_file:?}")
    })?;

    // Finalize TLS config
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .context("Failed to create TLS server config")?;

    Ok(config)
}
