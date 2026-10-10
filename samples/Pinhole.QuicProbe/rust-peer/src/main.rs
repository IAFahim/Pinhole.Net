use std::{error::Error, fs, io::Write, sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD};
use quinn::{Endpoint, ServerConfig, crypto::rustls::QuicServerConfig};
use rustls::{
    RootCertStore,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
use serde_json::json;

type Failure = Box<dyn Error + Send + Sync>;
const ALPN: &[u8] = b"pinhole-quic-probe/1";
const ECHOES: usize = 101;
const PAYLOAD: usize = 64;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Failure> {
    tokio::time::timeout(Duration::from_secs(20), run()).await??;
    Ok(())
}

async fn run() -> Result<(), Failure> {
    let path = std::env::args()
        .nth(1)
        .ok_or("Usage: pinhole-quic-peer <client.der>")?;
    let expected_client = fs::read(path)?;
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(expected_client.clone()))?;
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    let generated = rcgen::generate_simple_self_signed(vec!["quic-probe-server".into()])?;
    let certificate: CertificateDer<'static> = generated.cert.into();
    let private_key = PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der());
    let mut tls = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(verifier)
        .with_single_cert(vec![certificate.clone()], private_key.into())?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let mut config = ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let transport = Arc::get_mut(&mut config.transport).ok_or("Shared transport config")?;
    transport.max_concurrent_bidi_streams(1_u32.into());
    transport.max_concurrent_uni_streams(0_u32.into());
    let endpoint = Endpoint::server(config, "127.0.0.1:0".parse()?)?;
    println!(
        "{}",
        json!({
            "status": "READY", "endpoint": endpoint.local_addr()?.to_string(),
            "certificate": STANDARD.encode(certificate.as_ref()), "quinn": "0.11.12"
        })
    );
    std::io::stdout().flush()?;

    let connection = endpoint
        .accept()
        .await
        .ok_or("Endpoint stopped before connection")?
        .await?;
    let identity = connection
        .peer_identity()
        .ok_or("Missing TLS client identity")?;
    let certificates = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| "Unexpected peer identity type")?;
    if certificates.first().map(|cert| cert.as_ref()) != Some(expected_client.as_slice()) {
        return Err("TLS client certificate did not match the expected pin".into());
    }

    let (mut send, mut receive) = connection.accept_bi().await?;
    let mut buffer = [0_u8; PAYLOAD];
    for sequence in 0..ECHOES {
        receive.read_exact(&mut buffer).await?;
        if i32::from_le_bytes(buffer[..4].try_into()?) != sequence as i32 {
            return Err("Incorrect message sequence".into());
        }
        send.write_all(&buffer).await?;
    }
    if receive.read(&mut buffer[..1]).await?.is_some() {
        return Err("Unexpected trailing request bytes".into());
    }
    send.finish()?;
    match connection.closed().await {
        quinn::ConnectionError::ApplicationClosed(close) if close.error_code == 0_u32.into() => {}
        error => return Err(format!("Unexpected close: {error}").into()),
    }
    endpoint.close(0_u32.into(), b"probe complete");
    endpoint.wait_idle().await;
    println!(
        "{}",
        json!({
            "status": "PASS", "verifiedEchoes": ECHOES, "clientCertificateVerified": true
        })
    );
    Ok(())
}
