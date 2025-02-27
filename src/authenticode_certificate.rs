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
        let (sha1, sha256) = thumbprints(&certificate)?;
        Ok(Self {
            certificate,
            sha1,
            sha256,
        })
    }
}

fn thumbprints(cert: &Certificate) -> Result<(String, String), AuthenticodeError> {
    let mut bytes = Vec::new();
    let _ = cert.encode_to_vec(&mut bytes)?;

    let mut sha1_hasher = Sha1::new();
    sha1_hasher.input(&bytes);

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.input(&bytes);

    Ok((sha1_hasher.result_str(), sha256_hasher.result_str()))
}
