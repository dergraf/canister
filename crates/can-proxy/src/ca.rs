use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("failed to generate certificate: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("rustls error: {0}")]
    Rustls(#[from] rustls::Error),
}

pub struct DynamicCa {
    pub ca_cert_pem: String,
    ca_cert: Certificate,
}

impl DynamicCa {
    pub fn generate() -> Result<Self, CaError> {
        let mut params = CertificateParams::new(vec![]);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "Canister Dynamic CA");
        dn.push(DnType::OrganizationName, "Canister Sandbox");
        params.distinguished_name = dn;

        let key_pair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?;
        params.key_pair = Some(key_pair);

        let ca_cert = Certificate::from_params(params)?;

        // A CA signs itself.
        let ca_cert_pem = ca_cert.serialize_pem()?;

        Ok(Self {
            ca_cert_pem,
            ca_cert,
        })
    }

    pub fn generate_server_cert(
        &self,
        domain: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), CaError> {
        let mut params = CertificateParams::new(vec![domain.to_string()]);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, domain);
        params.distinguished_name = dn;

        let key_pair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?;
        let private_key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
        params.key_pair = Some(key_pair);

        let cert = Certificate::from_params(params)?;
        let cert_der = cert.serialize_der_with_signer(&self.ca_cert)?;

        let cert_der = CertificateDer::from(cert_der);
        Ok((cert_der, private_key_der))
    }
}
