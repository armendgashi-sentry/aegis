use std::path::Path;
use std::sync::Arc;

use dashmap::DashMap;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, DnValue, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, BasicConstraints, Certificate,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;

/// Manages CA certificate and dynamically generates per-host leaf certificates for MITM.
pub struct CertAuthority {
    ca_cert: Certificate,
    ca_key_pair: Arc<KeyPair>,
    ca_cert_der: CertificateDer<'static>,
    /// Cache of generated TLS acceptors per hostname
    cache: DashMap<String, Arc<TlsAcceptor>>,
}

impl CertAuthority {
    /// Load or generate a CA certificate.
    pub fn load_or_generate(
        cert_path: &Path,
        key_path: &Path,
        auto_generate: bool,
    ) -> anyhow::Result<Self> {
        if cert_path.exists() && key_path.exists() {
            Self::load_existing(cert_path, key_path)
        } else if auto_generate {
            let ca = Self::generate_new()?;
            ca.save(cert_path, key_path)?;
            Ok(ca)
        } else {
            anyhow::bail!(
                "CA certificate not found at {} and auto_generate_ca is disabled",
                cert_path.display()
            )
        }
    }

    /// Generate a new self-signed CA certificate.
    fn generate_new() -> anyhow::Result<Self> {
        let key_pair = KeyPair::generate()?;

        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, DnValue::Utf8String("Aegis Proxy CA".into()));
        dn.push(DnType::OrganizationName, DnValue::Utf8String("Aegis".into()));
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);

        let ca_cert = params.clone().self_signed(&key_pair)?;
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        Ok(Self {
            ca_cert,
            ca_key_pair: Arc::new(key_pair),
            ca_cert_der,
            cache: DashMap::new(),
        })
    }

    /// Load an existing CA from PEM files.
    fn load_existing(cert_path: &Path, key_path: &Path) -> anyhow::Result<Self> {
        let key_pem = std::fs::read_to_string(key_path)?;
        let key_pair = KeyPair::from_pem(&key_pem)?;

        let cert_pem = std::fs::read_to_string(cert_path)?;
        let cert_der_data = pem::parse(&cert_pem)?.into_contents();
        let _loaded_der = CertificateDer::from(cert_der_data);

        // Re-generate the CA params and self-sign to get a Certificate object
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, DnValue::Utf8String("Aegis Proxy CA".into()));
        dn.push(DnType::OrganizationName, DnValue::Utf8String("Aegis".into()));
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        params.not_before = time::OffsetDateTime::now_utc();
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(3650);

        let ca_cert = params.self_signed(&key_pair)?;
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        Ok(Self {
            ca_cert,
            ca_key_pair: Arc::new(key_pair),
            ca_cert_der,
            cache: DashMap::new(),
        })
    }

    /// Save CA cert and key to PEM files.
    fn save(&self, cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
        if let Some(parent) = cert_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let cert_pem = pem::encode(&pem::Pem::new("CERTIFICATE", self.ca_cert_der.to_vec()));
        std::fs::write(cert_path, &cert_pem)?;

        let key_pem = self.ca_key_pair.serialize_pem();
        std::fs::write(key_path, &key_pem)?;

        tracing::info!("CA certificate saved to {} and {}", cert_path.display(), key_path.display());
        Ok(())
    }

    /// Get or create a TLS acceptor for the given hostname.
    pub fn get_tls_acceptor(&self, hostname: &str) -> anyhow::Result<Arc<TlsAcceptor>> {
        if let Some(acceptor) = self.cache.get(hostname) {
            return Ok(acceptor.clone());
        }

        let acceptor = Arc::new(self.create_tls_acceptor(hostname)?);
        self.cache.insert(hostname.to_string(), acceptor.clone());
        Ok(acceptor)
    }

    /// Create a TLS acceptor with a dynamically generated leaf certificate.
    fn create_tls_acceptor(&self, hostname: &str) -> anyhow::Result<TlsAcceptor> {
        let leaf_key = KeyPair::generate()?;

        let mut leaf_params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, DnValue::Utf8String(hostname.into()));
        leaf_params.distinguished_name = dn;
        leaf_params.is_ca = IsCa::NoCa;
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.subject_alt_names = vec![
            rcgen::SanType::DnsName(hostname.try_into()?),
        ];
        leaf_params.not_before = time::OffsetDateTime::now_utc();
        leaf_params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(365);

        let leaf_cert = leaf_params.signed_by(
            &leaf_key,
            &self.ca_cert,
            &self.ca_key_pair,
        )?;

        let leaf_cert_der = CertificateDer::from(leaf_cert.der().to_vec());
        let leaf_key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf_cert_der, self.ca_cert_der.clone()],
                leaf_key_der,
            )?;

        server_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        Ok(TlsAcceptor::from(Arc::new(server_config)))
    }
}
