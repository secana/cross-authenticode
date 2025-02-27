#![allow(dead_code)]

use cms::{
    cert::x509::der::{Decode, Encode, EncodePem, SliceReader},
    content_info::ContentInfo,
    signed_data::SignedData,
};
use crypto::{
    digest::Digest,
    sha1::{self, Sha1},
};
use object::{LittleEndian, pe::IMAGE_DIRECTORY_ENTRY_SECURITY, read::pe::PeFile64};

#[derive(Debug)]
struct WinCertificate {
    length: u32,
    revision: u16,
    certificate_type: u16,
    certificate: Vec<u8>,
}

impl WinCertificate {
    fn new(data: &[u8], offset: u32) -> Self {
        let offset = offset as usize;
        let length = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        let revision = u16::from_le_bytes(data[offset + 4..offset + 6].try_into().unwrap());
        let certificate_type = u16::from_le_bytes(data[offset + 6..offset + 8].try_into().unwrap());
        // not sure about the "-8"...
        let certificate = data[offset + 8..(offset + length as usize)].to_vec();

        Self {
            length,
            revision,
            certificate_type,
            certificate,
        }
    }
}

fn get_export_dir(data: &[u8]) {
    let pe = PeFile64::parse(data).unwrap();

    let security_dir = pe.data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY).unwrap();
    let win_certificate = WinCertificate::new(data, security_dir.virtual_address.get(LittleEndian));

    let mut reader = SliceReader::new(&win_certificate.certificate).unwrap();
    let content_info = ContentInfo::decode(&mut reader).unwrap();

    let signed_data = content_info.content.decode_as::<SignedData>().unwrap();

    let certificates = signed_data
        .certificates
        .as_ref()
        .unwrap()
        .0
        .iter()
        .map(|cert| {
            if let cms::cert::CertificateChoices::Certificate(cert) = cert {
                cert
            } else {
                panic!()
            }
        });

    let mut i = 0;
    for cert in certificates {
        println!("Certificate {}", i);
        println!("Subject: {}", cert.tbs_certificate.subject);
        println!("Issuer: {}", cert.tbs_certificate.issuer);

        let pem = cert
            .to_pem(cms::cert::x509::der::pem::LineEnding::LF)
            .unwrap();

        std::fs::write(format!("cert-{}.pem", i), pem.as_str()).unwrap();

        let mut bytes = Vec::new();
        cert.encode_to_vec(&mut bytes).unwrap();

        let mut hasher = Sha1::new();

        hasher.input(&bytes);

        let hex = hasher.result_str();

        println!("SHA-1: {}", hex);
        println!("\n");

        i += 1;
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_get_export_dir() {
        // Cert-0
        // SHA-1: f55115d2439ce0a7529ffaaea654be2c71dce955
        // SHA256: 9267a08c9fc07b6ab194dc4df3121b264e825330a39ffc42cdb0942f5115eb97
        //
        // Cert-1
        // SHA-1: 580a6f4cc4e4b669b9ebdc1b2b3e087b80d0678d
        // SHA256: e8e95f0733a55e8bad7be0a1413ee23c51fcea64b3c8fa6a786935fddcc71961

        let pe_path = PathBuf::from("test-pe/test.bin");
        let pe_file = std::fs::read(pe_path).unwrap();
        get_export_dir(&pe_file);
    }
}
