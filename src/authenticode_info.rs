use crate::win_certificate::WinCertificate;
use crate::{authenticode_certificate::AuthenticodeCertificate, error::AuthenticodeError};
use cms::{
    cert::{
        CertificateChoices,
        x509::der::{Decode, SliceReader},
    },
    content_info::ContentInfo,
    signed_data::SignedData,
};
use object::{
    LittleEndian, pe::IMAGE_DIRECTORY_ENTRY_SECURITY, read::pe::PeFile32, read::pe::PeFile64,
};

/// Contains information about the Authenticode signature of a PE file.
#[derive(Debug)]
pub struct AuthenticodeInfo {
    /// List of certificates with additional information found in the PE file.
    pub certificates: Vec<AuthenticodeCertificate>,
}

impl AuthenticodeInfo {
    fn create(data: &[u8]) -> Result<AuthenticodeInfo, AuthenticodeError> {
        let win_certificate = Self::win_certificate(data)?;
        let signed_data = Self::signed_data(&win_certificate)?;
        let authenticode_certificates = Self::certificates(signed_data)?;

        Ok(AuthenticodeInfo {
            certificates: authenticode_certificates,
        })
    }

    fn signed_data(win_certificate: &WinCertificate) -> Result<SignedData, AuthenticodeError> {
        let mut reader = SliceReader::new(win_certificate.certificate)?;
        let content_info = ContentInfo::decode(&mut reader)?;
        let signed_data = content_info.content.decode_as::<SignedData>()?;
        Ok(signed_data)
    }

    fn win_certificate(data: &[u8]) -> Result<WinCertificate, AuthenticodeError> {
        let security_dir = match PeFile64::parse(data) {
            Ok(pe) => pe
                .data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
                .ok_or(AuthenticodeError::NoWinCertificate)?,
            Err(_) => PeFile32::parse(data)?
                .data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
                .ok_or(AuthenticodeError::NoWinCertificate)?,
        };

        let win_certificate =
            WinCertificate::new(data, security_dir.virtual_address.get(LittleEndian))?;

        Ok(win_certificate)
    }

    fn certificates(
        signed_data: SignedData,
    ) -> Result<Vec<AuthenticodeCertificate>, AuthenticodeError> {
        let authenticode_certificates = signed_data
            .certificates
            .as_ref()
            .ok_or(AuthenticodeError::NoCertificates)?
            .0
            .iter()
            .filter_map(|cert| match cert {
                CertificateChoices::Certificate(cert) => Some(cert),
                _ => None,
            })
            .map(|cert| AuthenticodeCertificate::try_from(cert.to_owned()))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(authenticode_certificates)
    }
}

/// Tries to create an `AuthenticodeInfo` struct from a slice of bytes.
impl TryFrom<&[u8]> for AuthenticodeInfo {
    type Error = AuthenticodeError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Self::create(data)
    }
}

/// Tries to create an `AuthenticodeInfo` struct from a vector of bytes.
impl TryFrom<&Vec<u8>> for AuthenticodeInfo {
    type Error = AuthenticodeError;

    fn try_from(data: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::create(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn sha1_thumbprints_signed_64() {
        let pe_path = PathBuf::from("test-pe/test-signed-64.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let ai = AuthenticodeInfo::try_from(&pe_file).unwrap();

        assert_eq!(ai.certificates.len(), 2);
        assert_eq!(
            ai.certificates[0].sha1,
            "f55115d2439ce0a7529ffaaea654be2c71dce955"
        );
        assert_eq!(
            ai.certificates[1].sha1,
            "580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d"
        );
    }

    #[test]
    fn sha256_thumbprints_signed_64() {
        let pe_path = PathBuf::from("test-pe/test-signed-64.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let ai = AuthenticodeInfo::try_from(&pe_file).unwrap();

        assert_eq!(ai.certificates.len(), 2);
        assert_eq!(
            ai.certificates[0].sha256,
            "9267a08c9fc07b6ab194dc4df3121b264e825330a39ffc42cdb0942f5115eb97"
        );
        assert_eq!(
            ai.certificates[1].sha256,
            "e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961"
        );
    }

    #[test]
    fn sha1_thumbprints_signed_32() {
        let pe_path = PathBuf::from("test-pe/test-signed-32.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let ai = AuthenticodeInfo::try_from(&pe_file).unwrap();

        assert_eq!(ai.certificates.len(), 2);
        assert_eq!(
            ai.certificates[0].sha1,
            "aeb9b61e47d91c42fff213992b7810a3d562fb12"
        );
        assert_eq!(
            ai.certificates[1].sha1,
            "580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d"
        );
    }

    #[test]
    fn sha256_thumbprints_signed_32() {
        let pe_path = PathBuf::from("test-pe/test-signed-32.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let ai = AuthenticodeInfo::try_from(&pe_file).unwrap();

        assert_eq!(ai.certificates.len(), 2);
        assert_eq!(
            ai.certificates[0].sha256,
            "bb91b9f1a11556a6556a804d0b5c984c3d1281a04dc918ab7b0a90d8b0747fde"
        );
        assert_eq!(
            ai.certificates[1].sha256,
            "e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961"
        );
    }

    #[test]
    fn no_cert_unsigned_32() {
        let pe_path = PathBuf::from("test-pe/test-unsigned-32.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let error = AuthenticodeInfo::try_from(&pe_file).err().unwrap();

        assert_eq!(error, AuthenticodeError::NoWinCertificate);
    }

    #[test]
    fn no_cert_unsigned_64() {
        let pe_path = PathBuf::from("test-pe/test-unsigned-64.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let error = AuthenticodeInfo::try_from(&pe_file).err().unwrap();

        assert_eq!(error, AuthenticodeError::NoWinCertificate);
    }

    #[test]
    fn not_a_pe_file() {
        let pe_path = PathBuf::from("test-pe/test-no-pe.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let error = AuthenticodeInfo::try_from(&pe_file).err().unwrap();

        assert_eq!(
            error,
            AuthenticodeError::ParsePe("Invalid DOS header size or alignment".to_string())
        );
    }
}
