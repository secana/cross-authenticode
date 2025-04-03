use crate::error::AuthenticodeError;
use cms::cert::x509::{Certificate, der::Encode};
use sha1::{Digest, Sha1};
use sha2::Sha256;

/// Contains information about an Authenticode certificate.
#[derive(Debug)]
pub struct AuthenticodeCertificate {
    /// The certificate itself, with all the information,
    /// e.g. Subject, Issuer etc.
    pub certificate: Certificate,
    /// The SHA1 thumbprint of the certificate.
    pub sha1: Vec<u8>,
    /// The SHA256 thumbprint of the certificate.
    pub sha256: Vec<u8>,
}

impl AuthenticodeCertificate {
    fn to_bytes(cert: &Certificate) -> Result<Vec<u8>, AuthenticodeError> {
        let mut bytes = Vec::new();
        let _ = cert.encode_to_vec(&mut bytes)?;
        Ok(bytes)
    }

    fn compute_sha1(bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Sha1::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }

    fn compute_sha256(bytes: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().to_vec()
    }
}

/// Tries to convert a CMS certificate to an Authenticode certificate.
impl TryFrom<Certificate> for AuthenticodeCertificate {
    type Error = AuthenticodeError;

    fn try_from(certificate: Certificate) -> Result<Self, Self::Error> {
        let bytes = Self::to_bytes(&certificate)?;
        Ok(Self {
            certificate,
            sha1: Self::compute_sha1(&bytes),
            sha256: Self::compute_sha256(&bytes),
        })
    }
}
