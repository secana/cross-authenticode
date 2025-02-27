use cms::cert::x509::{Certificate, der::Encode};
use crypto::{digest::Digest, sha1::Sha1, sha2::Sha256};

use crate::error::AuthenticodeError;

#[derive(Debug)]
pub struct AuthenticodeCertificate {
    pub certificate: Certificate,
    pub sha1: String,
    pub sha256: String,
}

impl AuthenticodeCertificate {
    pub fn new(certificate: Certificate) -> Result<Self, AuthenticodeError> {
        let sha1 = sha1_thumbprint(&certificate)?;
        let sha256 = sha256_thumbprint(&certificate)?;

        Ok(Self {
            certificate,
            sha1,
            sha256,
        })
    }
}

fn sha1_thumbprint(cert: &Certificate) -> Result<String, AuthenticodeError> {
    let mut bytes = Vec::new();
    let _ = cert.encode_to_vec(&mut bytes)?;

    let mut hasher = Sha1::new();
    hasher.input(&bytes);

    Ok(hasher.result_str())
}

fn sha256_thumbprint(cert: &Certificate) -> Result<String, AuthenticodeError> {
    let mut bytes = Vec::new();
    let _ = cert.encode_to_vec(&mut bytes);

    let mut hasher = Sha256::new();
    hasher.input(&bytes);

    Ok(hasher.result_str())
}
