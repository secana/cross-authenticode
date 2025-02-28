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
