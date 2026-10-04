use std::sync::Arc;

use anyhow::Context;
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

use crate::paths::TinyPaths;

/// Load TLS config from existing cert/key, or auto-generate a self-signed
/// pair with rcgen on first boot.
pub fn load_or_generate(paths: &TinyPaths) -> anyhow::Result<Arc<ServerConfig>> {
    if !paths.cert_file.exists() || !paths.key_file.exists() {
        generate_self_signed(paths)?;
    }
    let cert_pem = std::fs::read(&paths.cert_file).context("read cert.pem")?;
    let key_pem = std::fs::read(&paths.key_file).context("read key.pem")?;

    let certs: Vec<rustls_pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<_, _>>()
            .context("parse cert.pem")?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in cert.pem");
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .context("parse key.pem")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in key.pem"))?;

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("build rustls server config")?;
    Ok(Arc::new(config))
}

fn generate_self_signed(paths: &TinyPaths) -> anyhow::Result<()> {
    let subject = vec!["tinydb".to_string()];
    let cert = rcgen::generate_simple_self_signed(subject)
        .map_err(|e| anyhow::anyhow!("rcgen generate: {e}"))?;
    let cert_pem = cert.cert.pem();
    let key_pem = cert.signing_key.serialize_pem();

    std::fs::create_dir_all(&paths.certs_dir)?;
    std::fs::write(&paths.cert_file, cert_pem)?;
    std::fs::write(&paths.key_file, key_pem)?;

    // Restrict key permissions on unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&paths.key_file)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&paths.key_file, perms)?;
    }
    Ok(())
}

pub fn acceptor(config: Arc<ServerConfig>) -> TlsAcceptor {
    TlsAcceptor::from(config)
}
