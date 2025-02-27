use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthenticodeError {
    #[error("failed to read slice from PE file")]
    ReadSlice(#[from] std::array::TryFromSliceError),
    #[error("failed to parse PE file")]
    Parse(#[from] object::Error),
    #[error("contains no win_certificate")]
    NoWinCertificate,
    #[error("no valid DER certificate")]
    DerError,
    #[error("no certificates found")]
    NoCertificates,
}

impl From<cms::cert::x509::der::Error> for AuthenticodeError {
    fn from(_: cms::cert::x509::der::Error) -> Self {
        Self::DerError
    }
}
