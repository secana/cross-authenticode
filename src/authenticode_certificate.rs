use crate::error::AuthenticodeError;
use cms::cert::x509::{Certificate, der::Encode};
use sha1::{Sha1, Digest};
use sha2::Sha256;

/// Contains information about an Authenticode certificate.
#[derive(Debug)]
pub struct AuthenticodeCertificate {
    /// The certificate itself, with all the information,
    /// e.g. Subject, Issuer etc.
    pub certificate: Certificate,
    /// The SHA1 thumbprint of the certificate.
    pub sha1: String,
    /// The SHA256 thumbprint of the certificate.
    pub sha256: String,
}

impl AuthenticodeCertificate {
    fn thumbprints(cert: &Certificate) -> Result<(String, String), AuthenticodeError> {
        let mut bytes = Vec::new();
        let _ = cert.encode_to_vec(&mut bytes)?;
        
        
        let mut hasher = Sha1::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let sha1: String = result.iter().map(|byte| format!("{:02x}", byte)).collect();
        
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let result = hasher.finalize();
        let sha256: String = result.iter().map(|byte| format!("{:02x}", byte)).collect();
        
        Ok((sha1, sha256))
    }
}

/// Tries to convert a CMS certificate to an Authenticode certificate.
impl TryFrom<Certificate> for AuthenticodeCertificate {
    type Error = AuthenticodeError;

    fn try_from(certificate: Certificate) -> Result<Self, Self::Error> {
        let (sha1, sha256) = Self::thumbprints(&certificate)?;
        Ok(Self {
            certificate,
            sha1,
            sha256,
        })
    }
}
