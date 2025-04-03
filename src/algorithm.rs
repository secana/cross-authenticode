use std::fmt::Display;

use crate::error::AuthenticodeError;

/// The hash algorithm used to sign the PE file.
#[derive(Debug, PartialEq)]
pub enum Algorithm {
    Md5,
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl TryFrom<&[u8]> for Algorithm {
    type Error = AuthenticodeError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        match value.len() {
            16 => Ok(Algorithm::Md5),
            20 => Ok(Algorithm::Sha1),
            32 => Ok(Algorithm::Sha256),
            48 => Ok(Algorithm::Sha384),
            64 => Ok(Algorithm::Sha512),
            _ => Err(AuthenticodeError::InvalidHashAlgorithm),
        }
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Algorithm::Md5 => write!(f, "MD5"),
            Algorithm::Sha1 => write!(f, "SHA1"),
            Algorithm::Sha256 => write!(f, "SHA256"),
            Algorithm::Sha384 => write!(f, "SHA384"),
            Algorithm::Sha512 => write!(f, "SHA512"),
        }
    }
}
