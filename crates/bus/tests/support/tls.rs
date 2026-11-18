//! Certificates for the TLS tests. Each test run makes new keys. No key is in the repository.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};

/// A private certificate authority.
pub struct Authority {
    issuer: CertifiedIssuer<'static, KeyPair>,
}

/// A certificate and its private key, as PEM text.
pub struct Identity {
    pub certificate: String,
    pub key: String,
}

impl Authority {
    /// Makes an authority with a new key.
    pub fn new(name: &str) -> Self {
        let mut params = CertificateParams::new(Vec::new()).expect("valid parameters");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
        ];
        let key = KeyPair::generate().expect("a new key");
        Self {
            issuer: CertifiedIssuer::self_signed(params, key).expect("a certificate"),
        }
    }

    /// The certificate of the authority, as PEM text.
    pub fn certificate(&self) -> String {
        self.issuer.pem()
    }

    /// Issues a server certificate for the DNS names and IP addresses in `names`.
    pub fn server(&self, names: &[&str]) -> Identity {
        self.issue(
            names,
            "aegis test server",
            ExtendedKeyUsagePurpose::ServerAuth,
        )
    }

    /// Issues a client certificate.
    pub fn client(&self, name: &str) -> Identity {
        self.issue(&[], name, ExtendedKeyUsagePurpose::ClientAuth)
    }

    fn issue(&self, names: &[&str], common_name: &str, usage: ExtendedKeyUsagePurpose) -> Identity {
        let names: Vec<String> = names.iter().map(ToString::to_string).collect();
        let mut params = CertificateParams::new(names).expect("valid names");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate().expect("a new key");
        let certificate = params.signed_by(&key, &self.issuer).expect("a certificate");
        Identity {
            certificate: certificate.pem(),
            key: key.serialize_pem(),
        }
    }
}
