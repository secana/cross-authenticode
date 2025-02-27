mod authenticode_certificate;
mod error;
mod win_certificate;

use authenticode_certificate::AuthenticodeCertificate;
use cms::{
    cert::{
        CertificateChoices,
        x509::der::{Decode, SliceReader},
    },
    content_info::ContentInfo,
    signed_data::SignedData,
};
use error::AuthenticodeError;
use object::{LittleEndian, pe::IMAGE_DIRECTORY_ENTRY_SECURITY, read::pe::PeFile64};
use win_certificate::WinCertificate;

#[derive(Debug)]
pub struct AuthenticodeInfo {
    pub certificates: Vec<AuthenticodeCertificate>,
}

pub fn authenticode_info(data: &[u8]) -> Result<AuthenticodeInfo, AuthenticodeError> {
    // TODO: Support 32-bit PE files
    let pe = PeFile64::parse(data)?;

    let security_dir = pe
        .data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
        .ok_or(AuthenticodeError::NoWinCertificate)?;
    let win_certificate =
        WinCertificate::new(data, security_dir.virtual_address.get(LittleEndian))?;

    let mut reader = SliceReader::new(win_certificate.certificate)?;
    let content_info = ContentInfo::decode(&mut reader)?;

    let signed_data = content_info.content.decode_as::<SignedData>()?;

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

    Ok(AuthenticodeInfo {
        certificates: authenticode_certificates,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn compute_thumbprints() {
        let pe_path = PathBuf::from("test-pe/test.bin");
        let pe_file = std::fs::read(pe_path).unwrap();

        let ai = authenticode_info(&pe_file).unwrap();

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
