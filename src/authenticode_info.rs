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
use object::{LittleEndian, pe::IMAGE_DIRECTORY_ENTRY_SECURITY, read::pe::PeFile64};

#[derive(Debug)]
pub struct AuthenticodeInfo {
    pub certificates: Vec<AuthenticodeCertificate>,
}

impl AuthenticodeInfo {
    pub fn new(data: &[u8]) -> Result<Self, AuthenticodeError> {
        authenticode_info(data)
    }
}

fn authenticode_info(data: &[u8]) -> Result<AuthenticodeInfo, AuthenticodeError> {
    let win_certificate = win_certificate(data)?;
    let signed_data = signed_data(&win_certificate)?;
    let authenticode_certificates = certificates(signed_data)?;

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
    // TODO: Support 32-bit PE files
    let pe = PeFile64::parse(data)?;

    let security_dir = pe
        .data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
        .ok_or(AuthenticodeError::NoWinCertificate)?;
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
        .map(|cert| AuthenticodeCertificate::new(cert.to_owned()))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(authenticode_certificates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn compute_thumbprints() {
        let pe_path = PathBuf::from("test-pe/test.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let ai = AuthenticodeInfo::new(&pe_file).unwrap();

        assert_eq!(ai.certificates.len(), 2);
        assert_eq!(
            ai.certificates[0].sha1,
            "f55115d2439ce0a7529ffaaea654be2c71dce955"
        );
        assert_eq!(
            ai.certificates[0].sha256,
            "9267a08c9fc07b6ab194dc4df3121b264e825330a39ffc42cdb0942f5115eb97"
        );
        assert_eq!(
            ai.certificates[1].sha1,
            "580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d"
        );
        assert_eq!(
            ai.certificates[1].sha256,
            "e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961"
        );
    }
}
