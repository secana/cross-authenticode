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
