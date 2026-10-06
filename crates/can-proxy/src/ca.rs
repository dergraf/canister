use rcgen::{
    Certificate, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
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
        // Strict X.509 verification (OpenSSL's X509_STRICT, Python 3.13's
        // default) refuses a CA that does not state its key usage.
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
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
        // ... and a leaf that does not name the key that signed it.
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let key_pair = KeyPair::generate(&PKCS_ECDSA_P256_SHA256)?;
        let private_key_der = PrivateKeyDer::Pkcs8(key_pair.serialize_der().into());
        params.key_pair = Some(key_pair);

        let cert = Certificate::from_params(params)?;
        let cert_der = cert.serialize_der_with_signer(&self.ca_cert)?;

        let cert_der = CertificateDer::from(cert_der);
        Ok((cert_der, private_key_der))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::extensions::ParsedExtension;
    use x509_parser::prelude::{FromDer, X509Certificate};

    fn parse(der: &[u8]) -> X509Certificate<'_> {
        X509Certificate::from_der(der).expect("parse").1
    }

    fn subject_key_id(cert: &X509Certificate<'_>) -> Option<Vec<u8>> {
        cert.extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::SubjectKeyIdentifier(id) => Some(id.0.to_vec()),
                _ => None,
            })
    }

    fn authority_key_id(cert: &X509Certificate<'_>) -> Option<Vec<u8>> {
        cert.extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::AuthorityKeyIdentifier(aki) => {
                    aki.key_identifier.as_ref().map(|id| id.0.to_vec())
                }
                _ => None,
            })
    }

    /// Strict X.509 verification (OpenSSL's X509_STRICT, on by default in
    /// Python 3.13) refuses a CA without key usage and a leaf without an
    /// authority key identifier.
    #[test]
    fn certificates_satisfy_strict_x509_verification() {
        let ca = DynamicCa::generate().expect("ca");
        let ca_der = ca.ca_cert.serialize_der().expect("ca der");
        let ca_cert = parse(&ca_der);

        let usage = ca_cert
            .key_usage()
            .expect("key usage parses")
            .expect("the CA states its key usage");
        assert!(usage.value.key_cert_sign(), "the CA may sign certificates");
        let ca_key_id = subject_key_id(&ca_cert).expect("the CA names its key");

        let (leaf_der, _) = ca.generate_server_cert("api.example.com").expect("leaf");
        let leaf = parse(&leaf_der);
        assert_eq!(
            authority_key_id(&leaf),
            Some(ca_key_id),
            "the leaf names the key that signed it"
        );
        let eku = leaf
            .extended_key_usage()
            .expect("extended key usage parses")
            .expect("the leaf states what it is for");
        assert!(eku.value.server_auth);
    }
}
