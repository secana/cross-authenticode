#![allow(dead_code)]

use cms::{
    cert::x509::der::{Decode, SliceReader},
    content_info::ContentInfo,
    signed_data::SignedData,
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

    for cert in certificates {
        println!("Subject: {}", cert.tbs_certificate.subject);
        println!("Issuer: {}", cert.tbs_certificate.issuer);
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_get_export_dir() {
        let pe_path = PathBuf::from("test-pe/test.bin");
        let pe_file = std::fs::read(pe_path).unwrap();
        get_export_dir(&pe_file);
    }
}
