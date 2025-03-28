use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum AuthenticodeError {
    #[error("failed to read slice from PE file: {0}")]
    ReadSlice(String),

    #[error("failed to parse PE file: {0}")]
    ParsePe(String),

    #[error("contains no win_certificate")]
    NoWinCertificate,

    #[error("no valid DER certificate: {0}")]
    DerError(String),

    #[error("no certificates found")]
    NoCertificates,

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("invalid ASN.1 encoding: {0}")]
    Asn1Error(String),

    #[error("no encapsulated content found")]
    NoEncapsulatedContent,

    #[error("invalid encapsulated content type: {0}")]
    InvalidEncapsulatedContentType(String),

    #[error("invalid encapsulated content")]
    InvalidEncapsulatedContent,

    #[error("invalid content type: {0}")]
    InvalidContentType(String),

    #[error("invalid hash algorithm")]
    InvalidHashAlgorithm,
}

impl From<cms::cert::x509::der::Error> for AuthenticodeError {
    fn from(error: cms::cert::x509::der::Error) -> Self {
        Self::DerError(error.to_string())
    }
}

impl From<std::array::TryFromSliceError> for AuthenticodeError {
    fn from(error: std::array::TryFromSliceError) -> Self {
        Self::ReadSlice(error.to_string())
    }
}

impl From<object::Error> for AuthenticodeError {
    fn from(error: object::Error) -> Self {
        Self::ParsePe(error.to_string())
    }
}
